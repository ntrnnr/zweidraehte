//! Product scripts: parameter calculations and parameter validations.
//!
//! Products attach two kinds of script to their parameters. A
//! `ParameterCalculation` keeps a left-hand group of parameters (`L`) and a
//! right-hand group (`R`) consistent: editing an `L` member runs the
//! left-to-right transformation, editing an `R` member runs the right-to-left
//! one. A `ParameterValidation` decides whether an edit is acceptable before
//! the value is stored.
//!
//! Neither kind derives values continuously. The reference executes them only
//! while a user edits one parameter: validations gate the edit, the new value
//! is stored, and the calculations reachable from that parameter run once in
//! dependency order. Their results become ordinary stored values. Adding a
//! device, loading a project, and compiling a download never run a script,
//! so a device at its defaults downloads the product's authored defaults even
//! where a calculation would disagree with them.
//!
//! This module holds the parts which do not need a live device: the
//! dependency plan, the `context` argument parser and the script host. The
//! host follows the reference's classic JScript engine, which the reference
//! prefers on its own platform, rather than its portable fallbacks.

use std::collections::HashMap;

use crate::schema::{ParameterCalculation, ParameterTypeDef, ParameterValidation};

use super::model::ParameterValue;

// ================================================================================
// Calculation Plans
// ================================================================================

/// Which transformation of a calculation an edit selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// An `L` parameter changed; the `R` parameters are recomputed.
    LeftToRight,
    /// An `R` parameter changed; the `L` parameters are recomputed.
    RightToLeft,
}

/// One concrete calculation: a product-level calculation, or a module
/// definition's calculation bound to one module instance. Parameter IDs are
/// the configuration IDs of that scope (`ref` or `instance::ref`).
#[derive(Debug)]
pub(crate) struct CalculationEdges {
    pub left: Vec<String>,
    pub right: Vec<String>,
}

/// The calculations an edit of `changed` triggers, in execution order.
///
/// This mirrors the reference's planner. Starting at the edited parameter it
/// adds every calculation mentioning it, in declaration order; the direction
/// is left-to-right when the parameter is an `L` member and right-to-left
/// otherwise. A calculation's outputs then become parameters whose own
/// calculations are added in turn. A calculation already planned in the
/// opposite direction is not added again: editing `R` runs the right-to-left
/// transformation, whose `L` outputs must not immediately trigger the same
/// calculation left-to-right. The nodes are finally ordered topologically
/// from the edited parameter.
///
/// # Errors
/// A cyclic dependency yields no plan; the reference then runs nothing.
pub(crate) fn plan_for_change(
    calculations: &[CalculationEdges],
    changed: &str,
) -> Result<Vec<(usize, Direction)>, String> {
    let mut by_parameter: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, calculation) in calculations.iter().enumerate() {
        for parameter in calculation.left.iter().chain(&calculation.right) {
            let entry = by_parameter.entry(parameter.as_str()).or_default();
            if entry.last() != Some(&index) && !entry.contains(&index) {
                entry.push(index);
            }
        }
    }
    if !by_parameter.contains_key(changed) {
        return Ok(Vec::new());
    }

    let mut graph = PlanGraph {
        calculations,
        by_parameter: &by_parameter,
        nodes: Vec::new(),
        parameters: HashMap::new(),
        planned: HashMap::new(),
    };
    let start = graph.parameter_node(changed);
    graph.expand_parameter(start);

    // Kahn's algorithm, seeded with the edited parameter alone. Like the
    // reference, a node is queued once: a calculation writing back into an
    // already ordered node, typically the edited parameter itself, releases
    // that edge without re-queueing it, so only a cycle among the remaining
    // nodes leaves some of them unordered.
    let mut predecessors: Vec<usize> = graph.nodes.iter().map(|node| node.predecessors).collect();
    let mut visited = vec![false; graph.nodes.len()];
    let mut queue = std::collections::VecDeque::from([start]);
    let mut ordered = Vec::with_capacity(graph.nodes.len());
    while let Some(node) = queue.pop_front() {
        visited[node] = true;
        ordered.push(node);
        for &successor in &graph.nodes[node].successors {
            predecessors[successor] -= 1;
            if predecessors[successor] == 0 && !visited[successor] {
                queue.push_back(successor);
            }
        }
    }
    if ordered.len() != graph.nodes.len() {
        return Err(format!("the calculation chain starting at `{changed}` contains a cycle"));
    }
    Ok(ordered
        .into_iter()
        .filter_map(|node| match graph.nodes[node].kind {
            PlanNodeKind::Calculation(index, direction) => Some((index, direction)),
            PlanNodeKind::Parameter(_) => None,
        })
        .collect())
}

#[derive(Debug)]
enum PlanNodeKind {
    Parameter(String),
    Calculation(usize, Direction),
}

#[derive(Debug)]
struct PlanNode {
    kind: PlanNodeKind,
    successors: Vec<usize>,
    predecessors: usize,
}

#[derive(Debug)]
struct PlanGraph<'a> {
    calculations: &'a [CalculationEdges],
    by_parameter: &'a HashMap<&'a str, Vec<usize>>,
    nodes: Vec<PlanNode>,
    parameters: HashMap<String, usize>,
    planned: HashMap<usize, usize>,
}

impl PlanGraph<'_> {
    fn parameter_node(&mut self, id: &str) -> usize {
        let index = self.nodes.len();
        self.nodes.push(PlanNode {
            kind: PlanNodeKind::Parameter(id.to_owned()),
            successors: Vec::new(),
            predecessors: 0,
        });
        self.parameters.insert(id.to_owned(), index);
        index
    }

    fn link(&mut self, from: usize, to: usize) {
        if !self.nodes[from].successors.contains(&to) {
            self.nodes[from].successors.push(to);
            self.nodes[to].predecessors += 1;
        }
    }

    fn expand_parameter(&mut self, node: usize) {
        let PlanNodeKind::Parameter(id) = &self.nodes[node].kind else {
            unreachable!("caller passes a parameter node")
        };
        let id = id.clone();
        let Some(candidates) = self.by_parameter.get(id.as_str()) else { return };
        for &calculation in candidates {
            let direction = if self.calculations[calculation].left.contains(&id) {
                Direction::LeftToRight
            } else {
                Direction::RightToLeft
            };
            match self.planned.get(&calculation).copied() {
                Some(existing) => {
                    // TODO: confirm with the script parity harness that the
                    // reference skips, rather than rejects, a calculation
                    // reached in both directions.
                    if matches!(self.nodes[existing].kind, PlanNodeKind::Calculation(_, planned) if planned == direction)
                    {
                        self.link(node, existing);
                    }
                }
                None => {
                    let created = self.nodes.len();
                    self.nodes.push(PlanNode {
                        kind: PlanNodeKind::Calculation(calculation, direction),
                        successors: Vec::new(),
                        predecessors: 0,
                    });
                    self.planned.insert(calculation, created);
                    self.link(node, created);
                    self.expand_calculation(created, calculation, direction);
                }
            }
        }
    }

    fn expand_calculation(&mut self, node: usize, calculation: usize, direction: Direction) {
        let outputs = match direction {
            Direction::LeftToRight => &self.calculations[calculation].right,
            Direction::RightToLeft => &self.calculations[calculation].left,
        };
        for output in outputs.clone() {
            match self.parameters.get(&output).copied() {
                Some(existing) => self.link(node, existing),
                None => {
                    let created = self.parameter_node(&output);
                    self.link(node, created);
                    self.expand_parameter(created);
                }
            }
        }
    }
}

// ================================================================================
// Script Values
// ================================================================================

/// One parameter as a script sees it: its script-visible name, its current
/// value and the type which decides how values cross the boundary.
#[cfg_attr(not(feature = "javascript"), allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) struct ScriptBinding<'a> {
    pub name: String,
    pub value: ParameterValue,
    pub type_def: Option<&'a ParameterTypeDef>,
}

/// Product resources available to every script call. Without the
/// `javascript` feature only the fallbacks that refuse to run read it.
#[cfg_attr(not(feature = "javascript"), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScriptHost<'a> {
    /// The application's `Static/Script`, shared by all function-style
    /// calculations and validations, including those of module definitions.
    pub script: Option<&'a str>,
    /// `(number, name, text)` of each `Static/Messages/Message`.
    pub messages: &'a [(Option<i32>, &'a str, &'a str)],
}

/// The verdict of one validation function.
#[cfg_attr(not(feature = "javascript"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValidationOutcome {
    Valid,
    /// The product rejected the value, optionally with its own message.
    Invalid(Option<String>),
}

/// The script name of a calculation or validation parameter: its alias, or
/// the reference's name when the product omits the alias.
pub(crate) fn script_name(alias: Option<&str>, reference_name: Option<&str>, parameter_name: &str) -> String {
    alias
        .filter(|alias| !alias.is_empty())
        .or(reference_name)
        // TODO: confirm with the script parity harness that a reference
        // without `@Name` falls back to its parameter's name.
        .unwrap_or(parameter_name)
        .to_owned()
}

/// Expand a calculation's or validation's parameter string into the value of
/// its `context` argument.
///
/// `{{name}}` placeholders take the textual value of the executing module
/// instance's argument of that name, or `""` (two quote characters) when
/// there is none. The result is then parsed as the reference's lenient JSON:
/// unquoted property names such as `{ LR: 1 }` are common.
pub(crate) fn context_arguments(
    parameters: Option<&str>,
    argument: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<(String, ContextValue)>, String> {
    let Some(parameters) = parameters.filter(|parameters| !parameters.is_empty()) else { return Ok(Vec::new()) };
    let placeholder = regex::Regex::new(r"\{\{(?<arg>\w+)\}\}").expect("the placeholder pattern is valid");
    let expanded = placeholder.replace_all(parameters, |captures: &regex::Captures<'_>| {
        argument(&captures["arg"]).unwrap_or_else(|| "\"\"".to_owned())
    });
    // Arrays also become objects, so only the leading brace tells the
    // object the reference requires apart from them.
    match LenientJson::new(&expanded).document()? {
        ContextValue::Object(fields) if expanded.trim_start().starts_with('{') => Ok(fields),
        _ => Err(format!("script parameters {parameters:?} are not a JSON object")),
    }
}

/// A `context` member. Arrays become objects keyed `"0"`, `"1"`, … without a
/// `length`, as the reference's host objects do.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ContextValue {
    Null,
    Bool(bool),
    Integer(i64),
    Float(f64),
    Text(String),
    Object(Vec<(String, ContextValue)>),
}

/// The subset of Json.NET's tolerant reader seen in product files: comments,
/// single quotes, unquoted names, trailing commas and the special numbers.
struct LenientJson<'a> {
    text: &'a [u8],
    position: usize,
}

impl<'a> LenientJson<'a> {
    fn new(text: &'a str) -> Self {
        Self { text: text.as_bytes(), position: 0 }
    }

    fn document(&mut self) -> Result<ContextValue, String> {
        let value = self.value()?;
        self.skip_blank()?;
        if self.position != self.text.len() {
            return Err(self.error("trailing characters"));
        }
        Ok(value)
    }

    fn error(&self, reason: &str) -> String {
        format!("{reason} at byte {} of script parameters", self.position)
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.position).copied()
    }

    fn skip_blank(&mut self) -> Result<(), String> {
        loop {
            match (self.peek(), self.text.get(self.position + 1)) {
                (Some(byte), _) if byte.is_ascii_whitespace() => self.position += 1,
                (Some(b'/'), Some(b'/')) => {
                    while self.peek().is_some_and(|byte| byte != b'\n') {
                        self.position += 1;
                    }
                }
                (Some(b'/'), Some(b'*')) => {
                    let end = self.text[self.position + 2..]
                        .windows(2)
                        .position(|pair| pair == b"*/")
                        .ok_or_else(|| self.error("unterminated comment"))?;
                    self.position += end + 4;
                }
                _ => return Ok(()),
            }
        }
    }

    fn value(&mut self) -> Result<ContextValue, String> {
        self.skip_blank()?;
        match self.peek().ok_or_else(|| self.error("missing value"))? {
            b'{' => self.object(),
            b'[' => self.array(),
            quote @ (b'"' | b'\'') => self.string(quote).map(ContextValue::Text),
            _ => self.literal(),
        }
    }

    fn object(&mut self) -> Result<ContextValue, String> {
        self.position += 1;
        let mut fields = Vec::new();
        loop {
            self.skip_blank()?;
            match self.peek() {
                Some(b'}') => {
                    self.position += 1;
                    return Ok(ContextValue::Object(fields));
                }
                Some(quote @ (b'"' | b'\'')) => {
                    let name = self.string(quote)?;
                    fields.push((name, self.member_value()?));
                }
                Some(_) => {
                    let start = self.position;
                    while self.peek().is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')) {
                        self.position += 1;
                    }
                    if start == self.position {
                        return Err(self.error("invalid property name"));
                    }
                    let name = String::from_utf8_lossy(&self.text[start..self.position]).into_owned();
                    fields.push((name, self.member_value()?));
                }
                None => return Err(self.error("unterminated object")),
            }
            self.skip_blank()?;
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b'}') => {}
                _ => return Err(self.error("expected `,` or `}`")),
            }
        }
    }

    fn member_value(&mut self) -> Result<ContextValue, String> {
        self.skip_blank()?;
        if self.peek() != Some(b':') {
            return Err(self.error("expected `:`"));
        }
        self.position += 1;
        self.value()
    }

    fn array(&mut self) -> Result<ContextValue, String> {
        self.position += 1;
        let mut items = Vec::new();
        loop {
            self.skip_blank()?;
            if self.peek() == Some(b']') {
                self.position += 1;
                let fields = items.into_iter().enumerate().map(|(index, item)| (index.to_string(), item)).collect();
                return Ok(ContextValue::Object(fields));
            }
            items.push(self.value()?);
            self.skip_blank()?;
            match self.peek() {
                Some(b',') => self.position += 1,
                Some(b']') => {}
                _ => return Err(self.error("expected `,` or `]`")),
            }
        }
    }

    fn string(&mut self, quote: u8) -> Result<String, String> {
        self.position += 1;
        let mut bytes = Vec::new();
        loop {
            let byte = self.peek().ok_or_else(|| self.error("unterminated string"))?;
            self.position += 1;
            match byte {
                _ if byte == quote => return String::from_utf8(bytes).map_err(|_| self.error("invalid UTF-8")),
                b'\\' => {
                    let escaped = self.peek().ok_or_else(|| self.error("unterminated escape"))?;
                    self.position += 1;
                    match escaped {
                        b'n' => bytes.push(b'\n'),
                        b'r' => bytes.push(b'\r'),
                        b't' => bytes.push(b'\t'),
                        b'b' => bytes.push(0x08),
                        b'f' => bytes.push(0x0c),
                        b'u' => {
                            let digits = self
                                .text
                                .get(self.position..self.position + 4)
                                .and_then(|digits| std::str::from_utf8(digits).ok())
                                .and_then(|digits| u32::from_str_radix(digits, 16).ok())
                                .and_then(char::from_u32)
                                .ok_or_else(|| self.error("invalid unicode escape"))?;
                            self.position += 4;
                            bytes.extend_from_slice(digits.encode_utf8(&mut [0; 4]).as_bytes());
                        }
                        other => bytes.push(other),
                    }
                }
                _ => bytes.push(byte),
            }
        }
    }

    fn literal(&mut self) -> Result<ContextValue, String> {
        let start = self.position;
        while self.peek().is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')) {
            self.position += 1;
        }
        let token = std::str::from_utf8(&self.text[start..self.position]).expect("the token is ASCII");
        Ok(match token {
            "true" => ContextValue::Bool(true),
            "false" => ContextValue::Bool(false),
            "null" | "undefined" => ContextValue::Null,
            "NaN" => ContextValue::Float(f64::NAN),
            "Infinity" => ContextValue::Float(f64::INFINITY),
            "-Infinity" => ContextValue::Float(f64::NEG_INFINITY),
            _ if token.starts_with("0x") || token.starts_with("0X") => i64::from_str_radix(&token[2..], 16)
                .map(ContextValue::Integer)
                .map_err(|_| self.error("invalid hexadecimal number"))?,
            _ if token.contains(['.', 'e', 'E']) => {
                token.parse().map(ContextValue::Float).map_err(|_| self.error("invalid number"))?
            }
            // TODO: Json.NET reads a number with a leading zero as octal;
            // no product file in the catalog relies on it.
            _ => token.parse().map(ContextValue::Integer).map_err(|_| self.error("invalid literal"))?,
        })
    }
}

// ================================================================================
// Reference Value Conversions
// ================================================================================

/// `Convert.ToInt64(double)`: round half to even, refuse what does not fit.
#[cfg_attr(not(feature = "javascript"), allow(dead_code))]
fn integer_from_number(number: f64) -> Result<i64, String> {
    let rounded = number.round_ties_even();
    if rounded.is_finite() && rounded >= i64::MIN as f64 && rounded < i64::MAX as f64 {
        Ok(rounded as i64)
    } else {
        Err(format!("{number} does not fit an integer parameter"))
    }
}

/// `Double.ToString()` of the reference's runtime: fifteen significant
/// digits, exponent notation for exponents below -4 or above 14.
///
/// TODO: the reference formats with the user's culture, so a German
/// installation writes a decimal comma. Model the culture once projects
/// record it.
#[cfg_attr(not(feature = "javascript"), allow(dead_code))]
fn format_double(number: f64) -> String {
    if number.is_nan() {
        return "NaN".to_owned();
    }
    if number.is_infinite() {
        return if number > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if number == 0.0 {
        return "0".to_owned();
    }
    let scientific = format!("{number:.14e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("exponent notation contains `e`");
    let exponent: i32 = exponent.parse().expect("Rust writes a decimal exponent");
    let digits = mantissa.replace(['.', '-'], "");
    let digits = digits.trim_end_matches('0');
    let sign = if number < 0.0 { "-" } else { "" };
    if !(-4..15).contains(&exponent) {
        let (first, rest) = digits.split_at(1);
        let fraction = if rest.is_empty() { String::new() } else { format!(".{rest}") };
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        return format!("{sign}{first}{fraction}E{exponent_sign}{:02}", exponent.abs());
    }
    if exponent < 0 {
        let zeros = "0".repeat((-exponent - 1) as usize);
        return format!("{sign}0.{zeros}{digits}");
    }
    let integer_digits = exponent as usize + 1;
    if digits.len() <= integer_digits {
        format!("{sign}{digits}{}", "0".repeat(integer_digits - digits.len()))
    } else {
        format!("{sign}{}.{}", &digits[..integer_digits], &digits[integer_digits..])
    }
}

// ================================================================================
// The Script Host
// ================================================================================

#[cfg(feature = "javascript")]
mod host {
    use boa_engine::object::ObjectInitializer;
    use boa_engine::object::builtins::JsArray;
    use boa_engine::property::Attribute;
    use boa_engine::{Context, JsObject, JsString, JsValue, Source};

    use super::*;

    /// Host objects every function-style script call receives. They are
    /// JavaScript so that no native closure has to outlive one call.
    ///
    /// `expando` reproduces the reference's host objects: a script may read
    /// and assign their existing fields but adding one fails the call.
    const PRELUDE: &str = r#"(function (messagesByName, messagesByNumber) {
        function toInt32(value) {
            var number = Number(value);
            var floor = Math.floor(number);
            var difference = number - floor;
            if (difference > 0.5 || (difference === 0.5 && floor % 2 !== 0)) { floor += 1; }
            return floor;
        }
        var application = {
            getMessage: function (numberOrName) {
                if (numberOrName === null || numberOrName === undefined) { return ""; }
                var text = typeof numberOrName === "string"
                    ? messagesByName[numberOrName]
                    : messagesByNumber[String(toInt32(numberOrName))];
                return text === undefined ? "" : text;
            }
        };
        var log = {
            error: function (message) {},
            warn: function (message) {},
            info: function (message) {},
            Debug: function (message) {}
        };
        function expando(target) {
            var owns = Object.prototype.hasOwnProperty;
            return new Proxy(target, {
                set: function (fields, name, value) {
                    if (!owns.call(fields, name)) { throw new Error("Script tried to add field " + String(name)); }
                    fields[name] = value;
                    return true;
                },
                defineProperty: function (fields, name, descriptor) {
                    if (!owns.call(fields, name)) { throw new Error("Script tried to add field " + String(name)); }
                    return Reflect.defineProperty(fields, name, descriptor);
                },
                deleteProperty: function () { return false; }
            });
        }
        return { application: application, log: log, expando: expando };
    })"#;

    struct Session {
        context: Context,
        expando: JsObject,
    }

    impl Session {
        fn new(host: &ScriptHost<'_>, with_globals: bool) -> Result<Self, String> {
            let mut context = Context::default();
            // The reference imposes no limits. These only stop a runaway
            // script from hanging the caller.
            context.runtime_limits_mut().set_loop_iteration_limit(10_000_000);
            context.runtime_limits_mut().set_recursion_limit(512);

            let mut by_name = ObjectInitializer::new(&mut context);
            let mut seen_names = std::collections::HashSet::new();
            for (_, name, text) in host.messages {
                if seen_names.insert(*name) {
                    by_name.property(JsString::from(*name), JsString::from(*text), Attribute::all());
                }
            }
            let by_name = by_name.build();
            let mut by_number = ObjectInitializer::new(&mut context);
            let mut seen_numbers = std::collections::HashSet::new();
            for (number, _, text) in host.messages {
                if let Some(number) = number.filter(|number| seen_numbers.insert(*number)) {
                    by_number.property(JsString::from(number.to_string()), JsString::from(*text), Attribute::all());
                }
            }
            let by_number = by_number.build();

            let factory = context.eval(Source::from_bytes(PRELUDE)).map_err(|error| format!("script host: {error}"))?;
            let factory = factory.as_callable().expect("the prelude evaluates to a function");
            let parts = factory
                .call(&JsValue::undefined(), &[by_name.into(), by_number.into()], &mut context)
                .map_err(|error| format!("script host: {error}"))?
                .as_object()
                .expect("the prelude returns its host objects");
            let member = |name: &str, context: &mut Context| -> JsObject {
                parts
                    .get(JsString::from(name), context)
                    .ok()
                    .and_then(|value| value.as_object())
                    .expect("the prelude defines every host object")
            };
            let expando = member("expando", &mut context);
            if with_globals {
                // The reference registers both objects with their members
                // as globals, so `getMessage(3)` and `info("…")` resolve
                // without a qualifier.
                let application = member("application", &mut context);
                let log = member("log", &mut context);
                let mut globals = vec![("ApplicationProgram", application.clone()), ("Log", log.clone())];
                let function =
                    application.get(JsString::from("getMessage"), &mut context).expect("defined by the prelude");
                globals.push(("getMessage", function.as_object().expect("a function object")));
                for name in ["error", "warn", "info", "Debug"] {
                    let function = log.get(JsString::from(name), &mut context).expect("defined by the prelude");
                    globals.push((name, function.as_object().expect("a function object")));
                }
                for (name, value) in globals {
                    context
                        .register_global_property(JsString::from(name), value, Attribute::all())
                        .map_err(|error| format!("script host: {error}"))?;
                }
            }
            Ok(Self { context, expando })
        }

        fn eval(&mut self, source: &str) -> Result<JsValue, String> {
            self.context.eval(Source::from_bytes(source)).map_err(|error| error.to_string())
        }

        /// A plain object holding the fields, and its strict proxy.
        fn fields(&mut self, fields: Vec<(String, JsValue)>) -> Result<(JsObject, JsValue), String> {
            let mut builder = ObjectInitializer::new(&mut self.context);
            for (name, value) in fields {
                builder.property(JsString::from(name.as_str()), value, Attribute::all());
            }
            let target = builder.build();
            let proxy = self
                .expando
                .call(&JsValue::undefined(), &[target.clone().into()], &mut self.context)
                .map_err(|error| error.to_string())?;
            Ok((target, proxy))
        }

        fn context_value(&mut self, value: &ContextValue) -> Result<JsValue, String> {
            Ok(match value {
                ContextValue::Null => JsValue::null(),
                ContextValue::Bool(value) => JsValue::from(*value),
                ContextValue::Integer(value) => JsValue::from(*value as f64),
                ContextValue::Float(value) => JsValue::from(*value),
                ContextValue::Text(value) => JsValue::from(JsString::from(value.as_str())),
                ContextValue::Object(fields) => self.context_object(fields)?,
            })
        }

        fn context_object(&mut self, fields: &[(String, ContextValue)]) -> Result<JsValue, String> {
            let mut values = Vec::new();
            for (name, value) in fields {
                // The reference omits members whose value is `null`.
                if *value != ContextValue::Null {
                    values.push((name.clone(), self.context_value(value)?));
                }
            }
            Ok(self.fields(values)?.1)
        }

        /// `CoerceToScriptingType` of the reference's JScript engine.
        fn script_value(&mut self, binding: &ScriptBinding<'_>) -> Result<JsValue, String> {
            Ok(match &binding.value {
                ParameterValue::Integer(value) => JsValue::from(*value as f64),
                ParameterValue::Float(value) => JsValue::from(*value),
                ParameterValue::Text(value) => match binding.type_def {
                    Some(ParameterTypeDef::TypeColor(color)) => {
                        // The reference parses three-octet colours with
                        // `Color.FromArgb(r, g, b)`, which is opaque, and hands
                        // scripts `Color.ToArgb()`: a signed 32-bit integer
                        // with the alpha octet set, so `#FF0000` is -65536.
                        // TODO: four-octet spaces such as RGBW; the reference's
                        // parser reads only three octets of them.
                        let bytes = color
                            .space
                            .decode_value(value)
                            .ok_or_else(|| format!("{value:?} is not a valid {} colour", color.space.name()))?;
                        let number = bytes.iter().fold(0u32, |number, byte| (number << 8) | u32::from(*byte));
                        let argb = if bytes.len() == 3 { (0xFF00_0000 | number) as i32 } else { number as i32 };
                        JsValue::from(f64::from(argb))
                    }
                    _ => JsValue::from(JsString::from(value.as_str())),
                },
                ParameterValue::Bytes(bytes) => {
                    JsArray::from_iter(bytes.iter().map(|byte| JsValue::from(f64::from(*byte))), &mut self.context)
                        .into()
                }
            })
        }

        /// `CoerceToParameterType` of the reference's JScript engine.
        /// `None` keeps the parameter's value.
        ///
        /// The reference coerces undefined to null; its final parameter
        /// setter ignores null and retains the previous value.
        fn parameter_value(
            &mut self,
            value: &JsValue,
            binding: &ScriptBinding<'_>,
        ) -> Result<Option<ParameterValue>, String> {
            if value.is_null_or_undefined() {
                return Ok(None);
            }
            let name = &binding.name;
            if let Some(ParameterTypeDef::TypeRawData(_)) = binding.type_def {
                return self
                    .bytes(value)
                    .map(|bytes| Some(ParameterValue::Bytes(bytes)))
                    .map_err(|error| format!("`{name}`: {error}"));
            }
            if value.is_object() {
                return Err(format!("`{name}` received a non-scalar value"));
            }
            let text = value.as_string().map(|text| text.to_std_string_escaped());
            let number = |text: &str| -> Result<f64, String> {
                text.trim().parse::<f64>().map_err(|_| format!("`{name}` received the non-numeric text {text:?}"))
            };
            let converted = match binding.type_def {
                Some(ParameterTypeDef::TypeText(_) | ParameterTypeDef::TypeIpAddress(_)) => {
                    ParameterValue::Text(match (&text, value.as_boolean(), value.as_number()) {
                        (Some(text), _, _) => text.clone(),
                        (_, Some(boolean), _) => if boolean { "True" } else { "False" }.to_owned(),
                        (_, _, Some(number)) => format_double(number),
                        _ => return Err(format!("`{name}` received an unsupported value")),
                    })
                }
                Some(ParameterTypeDef::TypeFloat(_)) => {
                    ParameterValue::Float(match (&text, value.as_boolean(), value.as_number()) {
                        (Some(text), _, _) => number(text)?,
                        (_, Some(boolean), _) => f64::from(u8::from(boolean)),
                        (_, _, Some(number)) => number,
                        _ => return Err(format!("`{name}` received an unsupported value")),
                    })
                }
                Some(ParameterTypeDef::TypeColor(color)) => {
                    if let Some(text) = text.filter(|text| color.space.decode_value(text).is_some()) {
                        // TODO: confirm with the script parity harness how the
                        // reference stores a colour returned as text.
                        ParameterValue::Text(text)
                    } else {
                        let number = match (value.as_boolean(), value.as_number()) {
                            (Some(boolean), _) => f64::from(u8::from(boolean)),
                            (_, Some(number)) => number,
                            _ => return Err(format!("`{name}` received an unsupported colour")),
                        };
                        let raw = integer_from_number(number)? as i32 as u32;
                        let digits = usize::from(color.space.size_bits() / 4);
                        let mask = if digits >= 8 { u32::MAX } else { (1u32 << (digits * 4)) - 1 };
                        ParameterValue::Text(format!("#{:0digits$X}", raw & mask))
                    }
                }
                Some(
                    ParameterTypeDef::TypeNumber(_)
                    | ParameterTypeDef::TypeRestriction(_)
                    | ParameterTypeDef::TypeTime(_),
                ) => ParameterValue::Integer(match (&text, value.as_boolean(), value.as_number()) {
                    (Some(text), _, _) => text
                        .trim()
                        .parse::<i64>()
                        .map_err(|_| format!("`{name}` received the non-integer text {text:?}"))?,
                    (_, Some(boolean), _) => i64::from(boolean),
                    (_, _, Some(number)) => {
                        integer_from_number(number).map_err(|error| format!("`{name}`: {error}"))?
                    }
                    _ => return Err(format!("`{name}` received an unsupported value")),
                }),
                // Types without a canonical conversion keep the script's own
                // shape.
                _ => match (&text, value.as_boolean(), value.as_number()) {
                    (Some(text), _, _) => ParameterValue::Text(text.clone()),
                    (_, Some(boolean), _) => ParameterValue::Integer(i64::from(boolean)),
                    (_, _, Some(number)) if number.fract() == 0.0 => ParameterValue::Integer(
                        integer_from_number(number).map_err(|error| format!("`{name}`: {error}"))?,
                    ),
                    (_, _, Some(number)) => ParameterValue::Float(number),
                    _ => return Err(format!("`{name}` received an unsupported value")),
                },
            };
            // The reference's checked numeric setter enforces the declared
            // bounds after coercion. Check here so downstream calculations
            // cannot consume an invalid intermediate result. Editor access
            // checks do not apply: calculations can write hidden outputs.
            // TODO: verify the final setter constraints for other types.
            if let (Some(ParameterTypeDef::TypeNumber(number)), ParameterValue::Integer(value)) =
                (binding.type_def, &converted)
                && (*value < number.min_inclusive || *value > number.max_inclusive)
            {
                return Err(format!(
                    "`{name}`: {value} is outside the allowed range {}..={}",
                    number.min_inclusive, number.max_inclusive
                ));
            }
            Ok(Some(converted))
        }

        /// Bytes from an array-like value or from `"[1, 2, 3]"` text.
        fn bytes(&mut self, value: &JsValue) -> Result<Vec<u8>, String> {
            let byte = |number: f64| -> Result<u8, String> {
                u8::try_from(integer_from_number(number)?).map_err(|_| format!("{number} is not a byte"))
            };
            if let Some(text) = value.as_string() {
                let text = text.to_std_string_escaped();
                let inner = text
                    .strip_prefix('[')
                    .and_then(|text| text.strip_suffix(']'))
                    .ok_or_else(|| format!("{text:?} is not a byte list"))?;
                return inner
                    .split([',', ' '])
                    .filter(|item| !item.is_empty())
                    .map(|item| item.parse::<u8>().map_err(|_| format!("{item:?} is not a byte")))
                    .collect();
            }
            let object = value.as_object().ok_or("raw data needs an array of bytes")?;
            let length = object
                .get(JsString::from("length"), &mut self.context)
                .and_then(|length| length.to_number(&mut self.context))
                .map_err(|error| error.to_string())?;
            (0..length as u32)
                .map(|index| {
                    let item = object.get(index, &mut self.context).map_err(|error| error.to_string())?;
                    byte(item.to_number(&mut self.context).map_err(|error| error.to_string())?)
                })
                .collect()
        }

        fn context_argument(&mut self, fields: &[(String, ContextValue)]) -> Result<JsValue, String> {
            self.context_object(fields)
        }

        fn call_global(&mut self, function: &str, arguments: &[JsValue]) -> Result<JsValue, String> {
            let callable = self
                .context
                .global_object()
                .get(JsString::from(function), &mut self.context)
                .map_err(|error| error.to_string())?
                .as_callable()
                .ok_or_else(|| format!("the product script defines no function `{function}`"))?;
            callable.call(&JsValue::undefined(), arguments, &mut self.context).map_err(|error| error.to_string())
        }
    }

    pub(super) fn calculate_with_function(
        host: &ScriptHost<'_>,
        function: &str,
        inputs: &[ScriptBinding<'_>],
        outputs: &[ScriptBinding<'_>],
        context: &[(String, ContextValue)],
    ) -> Result<Vec<Option<ParameterValue>>, String> {
        let script = host.script.ok_or("the product has no Static/Script")?;
        let mut session = Session::new(host, true)?;
        session.eval(script)?;
        let mut fields = Vec::new();
        for binding in inputs {
            fields.push((binding.name.clone(), session.script_value(binding)?));
        }
        let (_, input) = session.fields(fields)?;
        let mut fields = Vec::new();
        for binding in outputs {
            fields.push((binding.name.clone(), session.script_value(binding)?));
        }
        let (output_fields, output) = session.fields(fields)?;
        let context = session.context_argument(context)?;
        session.call_global(function, &[input, output, context])?;
        outputs
            .iter()
            .map(|binding| {
                let value = output_fields
                    .get(JsString::from(binding.name.as_str()), &mut session.context)
                    .map_err(|error| error.to_string())?;
                session.parameter_value(&value, binding)
            })
            .collect()
    }

    pub(super) fn calculate_inline(
        body: &str,
        inputs: &[ScriptBinding<'_>],
        outputs: &[ScriptBinding<'_>],
    ) -> Result<Vec<Option<ParameterValue>>, String> {
        // The reference declares every alias globally and wraps the body in a
        // function, so `return` is legal and a `var` inside the body shadows
        // the output of the same name.
        let mut source = String::new();
        for binding in inputs.iter().chain(outputs) {
            source.push_str(&format!("var {};\n", binding.name));
        }
        source.push_str("function ParameterCalculation() {\n");
        source.push_str(body);
        source.push_str("\n}\n");

        // Inline calculations run without the function-style host objects.
        let host = ScriptHost { script: None, messages: &[] };
        let mut session = Session::new(&host, false)?;
        session.eval(&source)?;
        let global = session.context.global_object();
        for binding in inputs {
            let value = session.script_value(binding)?;
            global
                .set(JsString::from(binding.name.as_str()), value, true, &mut session.context)
                .map_err(|error| error.to_string())?;
        }
        session.call_global("ParameterCalculation", &[])?;
        outputs
            .iter()
            .map(|binding| {
                let value = global
                    .get(JsString::from(binding.name.as_str()), &mut session.context)
                    .map_err(|error| error.to_string())?;
                session.parameter_value(&value, binding)
            })
            .collect()
    }

    pub(super) fn validate(
        host: &ScriptHost<'_>,
        function: &str,
        inputs: &[ScriptBinding<'_>],
        changed: &ScriptBinding<'_>,
        context: &[(String, ContextValue)],
    ) -> Result<ValidationOutcome, String> {
        let script = host.script.ok_or("the product has no Static/Script")?;
        let mut session = Session::new(host, true)?;
        session.eval(script)?;
        let mut fields = Vec::new();
        for binding in inputs {
            fields.push((binding.name.clone(), session.script_value(binding)?));
        }
        let (_, input) = session.fields(fields)?;
        let new_value = session.script_value(changed)?;
        let context = session.context_argument(context)?;
        let changed_name = JsValue::from(JsString::from(changed.name.as_str()));
        let verdict = session.call_global(function, &[input, changed_name, new_value, context])?;

        // Falsy numbers and `false` reject the value; text rejects it with
        // the product's message. Anything else accepts it.
        Ok(if let Some(message) = verdict.as_string() {
            ValidationOutcome::Invalid(Some(message.to_std_string_escaped()))
        } else if let Some(valid) = verdict.as_boolean() {
            if valid { ValidationOutcome::Valid } else { ValidationOutcome::Invalid(None) }
        } else if let Some(number) = verdict.as_number() {
            if number != 0.0 { ValidationOutcome::Valid } else { ValidationOutcome::Invalid(None) }
        } else {
            ValidationOutcome::Valid
        })
    }
}

/// Run one planned calculation and return its outputs in binding order.
/// `None` keeps an output's stored value.
///
/// # Errors
/// Unsupported languages, script failures and unconvertible results.
pub(crate) fn execute_calculation(
    host: &ScriptHost<'_>,
    calculation: &ParameterCalculation,
    direction: Direction,
    inputs: &[ScriptBinding<'_>],
    outputs: &[ScriptBinding<'_>],
    argument: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<Option<ParameterValue>>, String> {
    let non_empty = |text: &Option<String>| text.as_deref().filter(|text| !text.is_empty()).map(str::to_owned);
    let keep = || Ok(vec![None; outputs.len()]);
    let (function, parameters, body) = match direction {
        Direction::LeftToRight => (
            non_empty(&calculation.lr_transformation_func),
            calculation.lr_transformation_parameters.as_deref(),
            non_empty(&calculation.lr_transformation),
        ),
        Direction::RightToLeft => (
            non_empty(&calculation.rl_transformation_func),
            calculation.rl_transformation_parameters.as_deref(),
            non_empty(&calculation.rl_transformation),
        ),
    };

    // A calculation with any function name is function-style in both
    // directions; a missing name for this direction makes it a no-op. The
    // product script is always JavaScript, whatever `@Language` says.
    if non_empty(&calculation.lr_transformation_func).is_some()
        || non_empty(&calculation.rl_transformation_func).is_some()
    {
        let Some(function) = function else { return keep() };
        let context = context_arguments(parameters, argument)?;
        return run_function(host, &function, inputs, outputs, &context);
    }
    let Some(body) = body else { return keep() };
    match calculation.language.to_ascii_lowercase().as_str() {
        "javascript" => run_inline(&body, inputs, outputs),
        // TODO: interpret VBScript. Product bodies use `Dim`, `If`,
        // `While`, `Select Case`, integer division, `&H` literals and only
        // `CInt`, `Int`, `CLng`, `CByte`, `CDbl`, `CStr`, `IsNumeric` and
        // `Round`; the reference's own portable interpreter supports the
        // same subset.
        "vbscript" => Err(format!("calculation `{}` needs a VBScript interpreter", calculation.id)),
        other => Err(format!("calculation `{}` uses unsupported language `{other}`", calculation.id)),
    }
}

/// Run one validation for an edit of `changed`.
///
/// # Errors
/// Script failures; a rejection is an `Ok` outcome.
pub(crate) fn execute_validation(
    host: &ScriptHost<'_>,
    validation: &ParameterValidation,
    inputs: &[ScriptBinding<'_>],
    changed: &ScriptBinding<'_>,
    argument: &dyn Fn(&str) -> Option<String>,
) -> Result<ValidationOutcome, String> {
    if validation.validation_func.is_empty() {
        return Ok(ValidationOutcome::Valid);
    }
    let context = context_arguments(validation.validation_parameters.as_deref(), argument)?;
    run_validation(host, &validation.validation_func, inputs, changed, &context)
}

#[cfg(feature = "javascript")]
fn run_function(
    host: &ScriptHost<'_>,
    function: &str,
    inputs: &[ScriptBinding<'_>],
    outputs: &[ScriptBinding<'_>],
    context: &[(String, ContextValue)],
) -> Result<Vec<Option<ParameterValue>>, String> {
    host::calculate_with_function(host, function, inputs, outputs, context)
}

#[cfg(feature = "javascript")]
fn run_inline(
    body: &str,
    inputs: &[ScriptBinding<'_>],
    outputs: &[ScriptBinding<'_>],
) -> Result<Vec<Option<ParameterValue>>, String> {
    host::calculate_inline(body, inputs, outputs)
}

#[cfg(feature = "javascript")]
fn run_validation(
    host: &ScriptHost<'_>,
    function: &str,
    inputs: &[ScriptBinding<'_>],
    changed: &ScriptBinding<'_>,
    context: &[(String, ContextValue)],
) -> Result<ValidationOutcome, String> {
    host::validate(host, function, inputs, changed, context)
}

#[cfg(not(feature = "javascript"))]
fn run_function(
    _host: &ScriptHost<'_>,
    function: &str,
    _inputs: &[ScriptBinding<'_>],
    _outputs: &[ScriptBinding<'_>],
    _context: &[(String, ContextValue)],
) -> Result<Vec<Option<ParameterValue>>, String> {
    Err(format!("script function `{function}` requires the `javascript` feature"))
}

#[cfg(not(feature = "javascript"))]
fn run_inline(
    _body: &str,
    _inputs: &[ScriptBinding<'_>],
    _outputs: &[ScriptBinding<'_>],
) -> Result<Vec<Option<ParameterValue>>, String> {
    Err("an inline calculation requires the `javascript` feature".to_owned())
}

#[cfg(not(feature = "javascript"))]
fn run_validation(
    _host: &ScriptHost<'_>,
    function: &str,
    _inputs: &[ScriptBinding<'_>],
    _changed: &ScriptBinding<'_>,
    _context: &[(String, ContextValue)],
) -> Result<ValidationOutcome, String> {
    Err(format!("validation function `{function}` requires the `javascript` feature"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edges(left: &[&str], right: &[&str]) -> CalculationEdges {
        CalculationEdges {
            left: left.iter().map(|id| (*id).to_owned()).collect(),
            right: right.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    #[test]
    fn plans_follow_edit_direction_and_dependencies() {
        // a → b (calc 0), b → c (calc 1), and c also feeds d through calc 2.
        let calculations = [edges(&["a"], &["b"]), edges(&["b"], &["c"]), edges(&["c"], &["d"])];
        assert_eq!(plan_for_change(&calculations, "a").expect("acyclic"), [
            (0, Direction::LeftToRight),
            (1, Direction::LeftToRight),
            (2, Direction::LeftToRight)
        ]);
        // Editing `b` runs calc 0 backwards and calc 1 forwards; calc 0's
        // recomputed `a` does not plan calc 0 a second time.
        assert_eq!(plan_for_change(&calculations, "b").expect("acyclic"), [
            (0, Direction::RightToLeft),
            (1, Direction::LeftToRight),
            (2, Direction::LeftToRight)
        ]);
        assert!(plan_for_change(&calculations, "unrelated").expect("acyclic").is_empty());
    }

    #[test]
    fn a_diamond_runs_its_join_after_both_branches() {
        let calculations = [edges(&["a"], &["b"]), edges(&["a"], &["c"]), edges(&["b", "c"], &["d"])];
        let plan = plan_for_change(&calculations, "a").expect("acyclic");
        assert_eq!(plan.last(), Some(&(2, Direction::LeftToRight)));
        assert_eq!(plan.len(), 3);
    }

    #[test]
    fn a_chain_writing_back_into_the_edited_parameter_is_no_cycle() {
        // Editing `b` runs calc 0 backwards into `a`; `a` feeds `c`, whose
        // calculation writes `b` again. The reference plans all three.
        let calculations = [edges(&["a"], &["b"]), edges(&["a"], &["c"]), edges(&["c"], &["b"])];
        assert_eq!(plan_for_change(&calculations, "b").expect("only the edited parameter is revisited"), [
            (0, Direction::RightToLeft),
            (1, Direction::LeftToRight),
            (2, Direction::LeftToRight)
        ]);
    }

    #[test]
    fn cyclic_chains_yield_no_plan() {
        let calculations = [edges(&["a"], &["b"]), edges(&["b"], &["c"]), edges(&["c"], &["b"])];
        assert!(plan_for_change(&calculations, "a").is_err());
    }

    #[test]
    fn context_parameters_accept_json_net_leniency_and_module_arguments() {
        let argument = |name: &str| (name == "Channel").then(|| "3".to_owned());
        let fields = context_arguments(
            Some("{ LR: 1, 'name': \"x\", channel: {{Channel}}, missing: {{Other}}, list: [4, 5.5,], /* note */ }"),
            &argument,
        )
        .expect("lenient JSON");
        assert_eq!(fields, [
            ("LR".to_owned(), ContextValue::Integer(1)),
            ("name".to_owned(), ContextValue::Text("x".to_owned())),
            ("channel".to_owned(), ContextValue::Integer(3)),
            ("missing".to_owned(), ContextValue::Text(String::new())),
            (
                "list".to_owned(),
                ContextValue::Object(vec![
                    ("0".to_owned(), ContextValue::Integer(4)),
                    ("1".to_owned(), ContextValue::Float(5.5)),
                ])
            ),
        ]);
        assert!(context_arguments(Some(""), &argument).expect("empty").is_empty());
        assert!(context_arguments(Some("[1]"), &argument).is_err());
    }

    #[test]
    fn doubles_format_like_the_reference_runtime() {
        assert_eq!(format_double(5.0), "5");
        assert_eq!(format_double(0.1 + 0.2), "0.3");
        assert_eq!(format_double(-1.5), "-1.5");
        assert_eq!(format_double(1e15), "1E+15");
        assert_eq!(format_double(123456789012345.0), "123456789012345");
        assert_eq!(format_double(0.0001), "0.0001");
        assert_eq!(format_double(0.00001), "1E-05");
    }

    #[test]
    fn integers_round_half_to_even() {
        assert_eq!(integer_from_number(2.5), Ok(2));
        assert_eq!(integer_from_number(3.5), Ok(4));
        assert_eq!(integer_from_number(-2.7), Ok(-3));
        assert!(integer_from_number(f64::NAN).is_err());
    }

    #[cfg(feature = "javascript")]
    mod javascript {
        use super::*;
        use crate::schema::{TypeNumber, TypeRawData};

        fn number_type() -> ParameterTypeDef {
            ParameterTypeDef::TypeNumber(TypeNumber {
                size_in_bit: 16,
                num_type: "unsignedInt".to_owned(),
                min_inclusive: 0,
                max_inclusive: 65535,
            })
        }

        fn binding<'a>(name: &str, value: ParameterValue, type_def: Option<&'a ParameterTypeDef>) -> ScriptBinding<'a> {
            ScriptBinding { name: name.to_owned(), value, type_def }
        }

        #[test]
        fn function_calculations_see_inputs_outputs_context_and_host_objects() {
            let number = number_type();
            let script = r#"
                function Scale(input, output, context) {
                    Log.info("scaling");
                    info("unqualified host members resolve too");
                    output.target = context.LR ? input.source * context.factor : output.target;
                    output.label = ApplicationProgram.getMessage(2) + "/" + getMessage("Second");
                }
            "#;
            let messages = [(Some(2), "First", "two"), (Some(3), "Second", "three")];
            let host = ScriptHost { script: Some(script), messages: &messages };
            let context = context_arguments(Some("{ LR: 1, factor: 2.5 }"), &|_| None).expect("context");
            let values = host::calculate_with_function(
                &host,
                "Scale",
                &[binding("source", ParameterValue::Integer(5), Some(&number))],
                &[
                    binding("target", ParameterValue::Integer(0), Some(&number)),
                    binding("label", ParameterValue::Text(String::new()), None),
                ],
                &context,
            )
            .expect("calculation runs");
            // 12.5 rounds half to even, as `Convert.ChangeType` does.
            assert_eq!(values, [Some(ParameterValue::Integer(12)), Some(ParameterValue::Text("two/three".to_owned()))]);
        }

        #[test]
        fn colours_reach_scripts_as_opaque_argb_integers() {
            let color = ParameterTypeDef::TypeColor(crate::schema::TypeColor { space: crate::schema::ColorSpace::Rgb });
            let host = ScriptHost {
                script: Some("function Read(input, output, context) { output.argb = input.colour; }"),
                messages: &[],
            };
            let values = host::calculate_with_function(
                &host,
                "Read",
                &[binding("colour", ParameterValue::Text("#FF0000".to_owned()), Some(&color))],
                &[binding("argb", ParameterValue::Integer(0), None)],
                &[],
            )
            .expect("calculation runs");
            assert_eq!(values, [Some(ParameterValue::Integer(-65536))]);
        }

        #[test]
        fn host_objects_refuse_new_fields() {
            let host = ScriptHost {
                script: Some("function Add(input, output, context) { output.extra = 1; }"),
                messages: &[],
            };
            let error = host::calculate_with_function(
                &host,
                "Add",
                &[],
                &[binding("target", ParameterValue::Integer(0), None)],
                &[],
            )
            .expect_err("adding a field fails");
            assert!(error.contains("Script tried to add field extra"), "{error}");
        }

        #[test]
        fn inline_bodies_run_inside_a_function() {
            let number = number_type();
            let values = host::calculate_inline(
                "if (source > 3) { target = source * 2; return; }\ntarget = 1;",
                &[binding("source", ParameterValue::Integer(7), Some(&number))],
                &[binding("target", ParameterValue::Integer(0), Some(&number))],
            )
            .expect("inline body runs");
            assert_eq!(values, [Some(ParameterValue::Integer(14))]);

            // A local `var` shadows the declared output, which stays unset.
            let values = host::calculate_inline("var target = 9;", &[], &[binding(
                "target",
                ParameterValue::Integer(4),
                Some(&number),
            )])
            .expect("inline body runs");
            assert_eq!(values, [None]);
        }

        #[test]
        fn numeric_output_bounds_apply_to_the_coerced_integer() {
            let number = ParameterTypeDef::TypeNumber(TypeNumber {
                size_in_bit: 8,
                num_type: "signedInt".to_owned(),
                min_inclusive: -2,
                max_inclusive: 2,
            });
            let output = [binding("target", ParameterValue::Integer(1), Some(&number))];
            // Half-to-even coercion can land exactly on either bound.
            for (expression, expected) in [("-2.5", -2), ("2.5", 2), ("'-2'", -2), ("true", 1)] {
                let values = host::calculate_inline(&format!("target = {expression};"), &[], &output)
                    .expect("coerced output is in range");
                assert_eq!(values, [Some(ParameterValue::Integer(expected))]);
            }
            for expression in ["-2.6", "2.6", "'3'"] {
                let error = host::calculate_inline(&format!("target = {expression};"), &[], &output)
                    .expect_err("coerced output is out of range");
                assert!(error.contains("-2..=2"), "{expression}: {error}");
            }
            for expression in ["null", "undefined"] {
                let values = host::calculate_inline(&format!("target = {expression};"), &[], &output)
                    .expect("null output retains the previous value");
                assert_eq!(values, [None]);
            }
        }

        #[test]
        fn raw_data_crosses_as_an_array_of_numbers() {
            let raw = ParameterTypeDef::TypeRawData(TypeRawData { max_size: 4 });
            let host = ScriptHost {
                script: Some(
                    "function Flip(input, output, context) { output.copy = [input.bytes[1], input.bytes[0], input.bytes.length]; }",
                ),
                messages: &[],
            };
            let values = host::calculate_with_function(
                &host,
                "Flip",
                &[binding("bytes", ParameterValue::Bytes(vec![1, 2]), Some(&raw))],
                &[binding("copy", ParameterValue::Bytes(Vec::new()), Some(&raw))],
                &[],
            )
            .expect("calculation runs");
            assert_eq!(values, [Some(ParameterValue::Bytes(vec![2, 1, 2]))]);
        }

        #[test]
        fn validations_accept_reject_and_explain() {
            let number = number_type();
            let host = ScriptHost {
                script: Some(
                    r#"function Check(input, changed, newValue, context) {
                        if (changed !== "low") { return true; }
                        if (newValue > input.high) { return "low must not exceed high"; }
                        return newValue !== context.forbidden;
                    }"#,
                ),
                messages: &[],
            };
            let context = context_arguments(Some("{ forbidden: 7 }"), &|_| None).expect("context");
            let inputs = [
                binding("low", ParameterValue::Integer(9), Some(&number)),
                binding("high", ParameterValue::Integer(8), Some(&number)),
            ];
            let check = |value| {
                host::validate(
                    &host,
                    "Check",
                    &inputs,
                    &binding("low", ParameterValue::Integer(value), Some(&number)),
                    &context,
                )
                .expect("validation runs")
            };
            assert_eq!(check(3), ValidationOutcome::Valid);
            assert_eq!(check(7), ValidationOutcome::Invalid(None));
            assert_eq!(check(9), ValidationOutcome::Invalid(Some("low must not exceed high".to_owned())));
        }
    }
}
