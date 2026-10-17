//! Project-based KNX commissioning frontend.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::num::NonZeroU8;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zweidraehte_client::project::{
    BatchSelection, Error as ClientError, PlannedProjectDevice, ProgrammingBatchPlan, ProjectCommissioningSession,
    ProjectInputRequest, ProjectInputSources, ProjectOperation, ProjectOperationInputs, ProjectOperationRequest,
    ProjectProduct, ProjectSetupRequirement, ProjectStatusCache, ProjectStatusInputs, ProjectStatusRequest,
    ProjectSynchronization, build_project_keyring,
};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use dialoguer::{Select, theme::ColorfulTheme};

use zweidraehte_client::cli::{OptionalTargetArgs, SecurityArgs};
use zweidraehte_client::commissioning::{
    CommissioningCancellation, CommissioningEvent, CommissioningIntent, CommissioningStage, DifferentialDecision,
    DifferentialFallback, DifferentialPolicy, DownloadMode, ImageSpace, ProfileDiscovery, ProfileRequest,
    ProgrammingModePolling, TargetSelection, UnloadMode, VariantHint,
};
use zweidraehte_client::commissioning::{CompileOptions, ManagementCredential, ObservedTarget, ProgrammingFacts};
use zweidraehte_client::{BusTarget, MaskVersion};
use zweidraehte_ets_files::archive::{
    PackageCatalogLeaf, PackageCatalogOnlyReason, PackageInstantiation, PackageInstantiationBlock, PackageStore,
    StoredPackage,
};
#[cfg(test)]
use zweidraehte_ets_files::keyring::Keyring;
use zweidraehte_ets_files::product::IpConfigurationMode;
use zweidraehte_project::{
    CouplerRoutingPolicy, DataSecureMode, DecodedFdsk, DomainAddress, IpAssignment, IpDeviceConfiguration,
    IpLineConfiguration, IpSecurityIntent, IpServiceSecurity, IpTunnellingUserBinding, KeyId, KeyKind,
    KeyMaterialSource, KeyOrigin, KeyScope, Medium, ProductReference, ProjectDeviceDraft, ProjectDeviceId,
    ProjectInstallationId, ProjectPackageId, ProjectStore, RfDeviceMode, format_serial, parse_fdsk, parse_serial,
};

const DEFAULT_PROGRAMMING_MODE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Parser)]
#[command(about = "Check, program, read, and unload devices from a KNX project")]
struct Args {
    #[arg(long, default_value = "project.knx")]
    project: PathBuf,
    #[arg(long)]
    master_data: Option<PathBuf>,
    #[command(flatten)]
    target: OptionalTargetArgs,
    #[command(flatten)]
    security: SecurityArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an empty project and its matching key/sequence state
    Init,
    /// Index and retain a project-local `.knxprod` without adding a device
    ImportProduct {
        /// Complete ETS product package
        product: PathBuf,
    },
    /// Import a `.knxprod` and add one exact catalogue item as a device
    #[command(alias = "import-device")]
    Add {
        /// Logical project device identifier
        device: String,
        /// Complete ETS product package
        product: PathBuf,
        /// Desired individual address
        #[arg(long, value_parser = zweidraehte_client::cli::parse_ia)]
        address: zweidraehte_client::IndividualAddress,
        /// Device serial number, with or without the manufacturer separator
        #[arg(long, value_parser = parse_project_serial)]
        serial: Option<[u8; 6]>,
        /// 32-digit FDSK or CRC-checked KNX device certificate
        #[arg(long, visible_alias = "device-certificate", value_name = "FDSK")]
        fdsk: Option<String>,
        #[arg(long)]
        max_apdu: Option<u16>,
        /// Enable the product's Data Secure application capability
        #[arg(long)]
        data_secure: bool,
        #[command(flatten)]
        topology: AddTopologyArgs,
        /// Select `CatalogItem/@Id` without the interactive dialog
        #[arg(long, value_name = "ID")]
        catalog_item: Option<String>,
    },
    Check,
    /// Copy matching device and group credentials from an ETS keyring into
    /// this project's authoritative key store
    ImportKeyring,
    /// Export active project credentials and device sequence observations as an ETS keyring
    ExportKeyring {
        /// New `.knxkeys` file; existing files are never replaced
        #[arg(short, long, value_name = "FILE")]
        out: PathBuf,
        /// Keyring project label; defaults to the project directory name
        #[arg(long)]
        name: Option<String>,
    },
    Status,
    /// Assign the IA and establish secure management, without loading an application
    Address {
        device: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        dry_run: bool,
        /// Use the physical programming-button procedure instead of serial addressing
        #[arg(long)]
        program_ia: bool,
        /// Seconds to wait for a device to enter programming mode (default: 300)
        #[arg(long, value_name = "SECONDS", requires = "program_ia")]
        programming_mode_timeout: Option<u64>,
        #[arg(long, value_name = "MASK")]
        device_mask: Option<String>,
    },
    /// Download application and Security IO configuration without changing the IA
    Load {
        /// Device to load. Omit with `--affected` to load every changed device.
        device: Option<String>,
        /// Load every active device affected since its last successful
        /// deployment. Omit the device identifier.
        #[arg(long, conflicts_with = "device")]
        affected: bool,
        #[arg(long)]
        dry_run: bool,
        /// Force the complete application procedure instead of differential programming
        #[arg(long)]
        full: bool,
        #[arg(long, value_name = "MASK")]
        device_mask: Option<String>,
        #[arg(long, value_name = "DIR")]
        dump_blobs: Option<PathBuf>,
    },
    /// Commission the IA/security state when necessary, then load the application
    Program {
        /// Device to program. Omit with `--affected` to program every changed device.
        device: Option<String>,
        /// Program every active device affected since its last successful
        /// deployment. Omit the device identifier.
        #[arg(long, conflicts_with = "device")]
        affected: bool,
        #[arg(long)]
        dry_run: bool,
        /// Force the complete application procedure instead of differential programming
        #[arg(long)]
        full: bool,
        /// Use the physical programming-button procedure instead of serial addressing
        #[arg(long)]
        program_ia: bool,
        /// Seconds to wait for a device to enter programming mode (default: 300)
        #[arg(long, value_name = "SECONDS", requires = "program_ia")]
        programming_mode_timeout: Option<u64>,
        #[arg(long, value_name = "MASK")]
        device_mask: Option<String>,
        #[arg(long, value_name = "DIR")]
        dump_blobs: Option<PathBuf>,
    },
    Read {
        device: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Unload the selected device's application or complete configuration
    Unload {
        /// Device to unload
        device: String,
        /// Explicitly unload the application, IA, and security configuration
        #[arg(long, conflicts_with = "application", required_unless_present = "application")]
        all: bool,
        /// Unload only the application while retaining IA and security configuration
        #[arg(long, conflicts_with = "all", required_unless_present = "all")]
        application: bool,
    },
    Sync,
    RecoverState {
        #[arg(long)]
        client_floor: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProjectMedium {
    Tp1,
    Rf,
    Ip,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProjectRfMode {
    Ready,
    Multi,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProjectRouting {
    Filter,
    RouteAll,
    BlockAll,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProjectIpAssignment {
    Dhcp,
    Fixed,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProjectIpSecurity {
    Plain,
    Secure,
}

/// `add` may create the enclosing line as well as the device, so every
/// topology value needed by that new line is accepted here. Nothing is
/// inferred from a mask or product family.
#[derive(Debug, Clone, ClapArgs)]
struct AddTopologyArgs {
    #[arg(long, value_enum, default_value_t = ProjectMedium::Tp1)]
    medium: ProjectMedium,
    /// RF domain (`00:FA:12:34:56:78`) or KNX/IP routing multicast address
    #[arg(long)]
    domain: Option<String>,
    /// Per-device RF Medium Object mode
    #[arg(long, value_enum)]
    rf_mode: Option<ProjectRfMode>,
    /// Address-zero coupler routing policy
    #[arg(long, value_enum)]
    routing: Option<ProjectRouting>,
    /// KNX/IP project and installation IDs as `PROJECT.INSTALLATION`
    #[arg(long, value_name = "PROJECT.INSTALLATION")]
    project_installation_id: Option<String>,
    #[arg(long)]
    multicast_latency_tolerance: Option<u16>,
    #[arg(long)]
    sync_latency_fraction: Option<u8>,
    #[arg(long, value_enum)]
    ip_assignment: Option<ProjectIpAssignment>,
    #[arg(long)]
    ip_address: Option<Ipv4Addr>,
    #[arg(long)]
    subnet_mask: Option<Ipv4Addr>,
    #[arg(long)]
    default_gateway: Option<Ipv4Addr>,
    #[arg(long)]
    multicast_ttl: Option<u8>,
    #[arg(long)]
    friendly_name: Option<String>,
    #[arg(long, value_parser = zweidraehte_client::cli::parse_ia)]
    additional_address: Vec<zweidraehte_client::IndividualAddress>,
    #[arg(long, value_enum)]
    ip_routing: Option<ProjectIpSecurity>,
    #[arg(long, value_enum)]
    ip_device_management: Option<ProjectIpSecurity>,
    #[arg(long, value_enum)]
    ip_tunnelling: Option<ProjectIpSecurity>,
    #[arg(long, value_parser = parse_nonzero_user)]
    ip_password_user: Vec<NonZeroU8>,
    /// IP Secure tunnelling mapping as `USER:ADDRESS_INDEX`
    #[arg(long, value_parser = parse_tunnelling_user)]
    ip_tunnelling_user: Vec<IpTunnellingUserBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgrammingOperation {
    Address,
    Load,
    Program,
}

impl ProgrammingOperation {
    fn requested_intent(self, force_full: bool) -> CommissioningIntent {
        let download = if force_full { DownloadMode::Full } else { DownloadMode::Automatic };

        match self {
            Self::Address => CommissioningIntent::AssignAddress,
            Self::Load => CommissioningIntent::Download(download),
            Self::Program => CommissioningIntent::AssignAddressAndDownload(download),
        }
    }

    const fn includes_application(self) -> bool {
        matches!(self, Self::Load | Self::Program)
    }
}

impl From<ProjectMedium> for Medium {
    fn from(value: ProjectMedium) -> Self {
        match value {
            ProjectMedium::Tp1 => Self::Tp1,
            ProjectMedium::Rf => Self::Rf,
            ProjectMedium::Ip => Self::Ip,
        }
    }
}

struct DraftTopology {
    medium: Medium,
    domain: Option<DomainAddress>,
    ip_line: Option<IpLineConfiguration>,
    rf_mode: Option<RfDeviceMode>,
    ip: Option<IpDeviceConfiguration>,
    routing: Option<CouplerRoutingPolicy>,
}

impl AddTopologyArgs {
    fn to_draft(&self, address: zweidraehte_client::IndividualAddress) -> Result<DraftTopology> {
        let medium: Medium = self.medium.into();
        let any_ip_argument = self.project_installation_id.is_some()
            || self.multicast_latency_tolerance.is_some()
            || self.sync_latency_fraction.is_some()
            || self.ip_assignment.is_some()
            || self.ip_address.is_some()
            || self.subnet_mask.is_some()
            || self.default_gateway.is_some()
            || self.multicast_ttl.is_some()
            || self.friendly_name.is_some()
            || !self.additional_address.is_empty()
            || self.ip_routing.is_some()
            || self.ip_device_management.is_some()
            || self.ip_tunnelling.is_some()
            || !self.ip_password_user.is_empty()
            || !self.ip_tunnelling_user.is_empty();

        if medium != Medium::Ip && any_ip_argument {
            bail!("KNX/IP topology options require `--medium ip`");
        }

        let domain = match (medium, self.domain.as_deref()) {
            (Medium::Tp1, None) => None,
            (Medium::Tp1, Some(_)) => bail!("TP1 does not have a line domain"),
            (Medium::Rf, Some(value)) => Some(DomainAddress::Rf(parse_rf_domain(value)?)),
            (Medium::Rf, None) => bail!("RF requires `--domain` with six hexadecimal octets"),
            (Medium::Ip, Some(value)) => Some(DomainAddress::Ip(
                value
                    .parse::<Ipv4Addr>()
                    .context("while attempting to parse the KNX/IP routing multicast domain")?
                    .octets(),
            )),
            (Medium::Ip, None) => bail!("KNX/IP requires `--domain` with its routing multicast address"),
        };

        let rf_mode = match (medium, self.rf_mode) {
            (Medium::Rf, Some(ProjectRfMode::Ready)) => Some(RfDeviceMode::Ready),
            (Medium::Rf, Some(ProjectRfMode::Multi)) => Some(RfDeviceMode::Multi),
            (Medium::Rf, None) | (Medium::Tp1 | Medium::Ip, None) => None,
            (_, Some(_)) => bail!("`--rf-mode` requires `--medium rf`"),
        };
        let routing = self.routing.map(|policy| match policy {
            ProjectRouting::Filter => CouplerRoutingPolicy::Filter,
            ProjectRouting::RouteAll => CouplerRoutingPolicy::RouteAll,
            ProjectRouting::BlockAll => CouplerRoutingPolicy::BlockAll,
        });
        if address.device() == 0 && routing.is_none() {
            bail!("an address-zero coupler requires `--routing`");
        }
        if address.device() != 0 && routing.is_some() {
            bail!("`--routing` is only valid for an address-zero coupler");
        }

        let (ip_line, ip) = if medium == Medium::Ip {
            let project_installation_id = self
                .project_installation_id
                .as_deref()
                .map(parse_project_installation_id)
                .transpose()?
                .context("KNX/IP requires `--project-installation-id PROJECT.INSTALLATION`")?;
            let ip_line = IpLineConfiguration {
                project_installation_id,
                multicast_latency_tolerance_ms: self.multicast_latency_tolerance,
                sync_latency_fraction: self.sync_latency_fraction,
            };
            let any_device_ip = self.ip_assignment.is_some()
                || self.ip_address.is_some()
                || self.subnet_mask.is_some()
                || self.default_gateway.is_some()
                || self.multicast_ttl.is_some()
                || self.friendly_name.is_some()
                || !self.additional_address.is_empty()
                || self.ip_routing.is_some()
                || self.ip_device_management.is_some()
                || self.ip_tunnelling.is_some()
                || !self.ip_password_user.is_empty()
                || !self.ip_tunnelling_user.is_empty();
            let ip = if any_device_ip {
                let assignment = match self
                    .ip_assignment
                    .context("IP device configuration requires `--ip-assignment`")?
                {
                    ProjectIpAssignment::Dhcp => {
                        if self.ip_address.is_some() || self.subnet_mask.is_some() || self.default_gateway.is_some() {
                            bail!("DHCP must not specify `--ip-address`, `--subnet-mask`, or `--default-gateway`");
                        }
                        IpAssignment::AutomaticDhcp
                    }
                    ProjectIpAssignment::Fixed => IpAssignment::Fixed {
                        address: self.ip_address.context("fixed IP assignment requires `--ip-address`")?.octets(),
                        subnet_mask: self.subnet_mask.context("fixed IP assignment requires `--subnet-mask`")?.octets(),
                        default_gateway: self
                            .default_gateway
                            .context("fixed IP assignment requires `--default-gateway`")?
                            .octets(),
                    },
                };
                let security = match (self.ip_routing, self.ip_device_management, self.ip_tunnelling) {
                    (None, None, None) if self.ip_password_user.is_empty() && self.ip_tunnelling_user.is_empty() => {
                        None
                    }
                    (Some(routing), Some(device_management), Some(tunnelling)) => Some(IpSecurityIntent {
                        routing: routing.into(),
                        device_management: device_management.into(),
                        tunnelling: tunnelling.into(),
                        multicast_latency_tolerance_ms: self
                            .multicast_latency_tolerance
                            .context("IP Secure configuration requires `--multicast-latency-tolerance`")?,
                        sync_latency_fraction: self
                            .sync_latency_fraction
                            .context("IP Secure configuration requires `--sync-latency-fraction`")?,
                        tunnelling_users: self.ip_tunnelling_user.clone(),
                    }),
                    _ => bail!(
                        "IP Secure configuration requires `--ip-routing`, `--ip-device-management`, and `--ip-tunnelling`"
                    ),
                };
                Some(IpDeviceConfiguration {
                    assignment,
                    multicast_ttl: self.multicast_ttl.context("IP device configuration requires `--multicast-ttl`")?,
                    friendly_name: self
                        .friendly_name
                        .clone()
                        .context("IP device configuration requires `--friendly-name`")?,
                    additional_individual_addresses: self.additional_address.clone(),
                    security,
                    password_users: self.ip_password_user.clone(),
                })
            } else {
                None
            };
            (Some(ip_line), ip)
        } else {
            (None, None)
        };

        Ok(DraftTopology { medium, domain, ip_line, rf_mode, ip, routing })
    }
}

fn validate_ip_configuration_ownership(topology: &DraftTopology, mode: &IpConfigurationMode) -> Result<()> {
    match mode {
        IpConfigurationMode::Tool if topology.ip.is_none() => {
            bail!("this product declares IPConfig=Tool; provide its complete KNX/IP device configuration");
        }
        IpConfigurationMode::Custom if topology.ip.is_some() => {
            bail!("this product declares IPConfig=Custom; its product parameters own the KNX/IP device configuration");
        }
        IpConfigurationMode::Unknown(value) => bail!("product declares unknown IPConfig token `{value}`"),
        IpConfigurationMode::Tool | IpConfigurationMode::Custom => Ok(()),
    }
}

impl From<ProjectIpSecurity> for IpServiceSecurity {
    fn from(value: ProjectIpSecurity) -> Self {
        match value {
            ProjectIpSecurity::Plain => Self::Plain,
            ProjectIpSecurity::Secure => Self::Secure,
        }
    }
}

fn parse_rf_domain(value: &str) -> Result<[u8; 6]> {
    let compact: String = value.chars().filter(|character| *character != ':').collect();
    if compact.len() != 12 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("RF domain must contain exactly six hexadecimal octets");
    }
    let mut domain = [0; 6];
    for (index, byte) in domain.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .context("while attempting to parse the RF domain")?;
    }
    Ok(domain)
}

fn parse_project_installation_id(value: &str) -> Result<ProjectInstallationId> {
    let (project, installation) =
        value.split_once('.').context("project installation ID must be `PROJECT.INSTALLATION`")?;
    let project = project.parse::<u16>().context("while attempting to parse the KNX/IP project ID")?;
    let installation = installation.parse::<u8>().context("while attempting to parse the KNX/IP installation ID")?;
    ProjectInstallationId::new(project, installation)
        .context("project ID must be 0..4095 and installation ID must be 0..15")
}

fn parse_nonzero_user(value: &str) -> core::result::Result<NonZeroU8, String> {
    let value = value.parse::<u8>().map_err(|_| "IP user ID must be 1..255".to_owned())?;
    NonZeroU8::new(value).ok_or_else(|| "IP user ID zero is reserved".to_owned())
}

fn parse_tunnelling_user(value: &str) -> core::result::Result<IpTunnellingUserBinding, String> {
    let (user, address_index) =
        value.split_once(':').ok_or_else(|| "tunnelling user must be `USER:ADDRESS_INDEX`".to_owned())?;
    let user_id = parse_nonzero_user(user)?;
    let address_index = address_index.parse::<u8>().map_err(|_| "address index must be 0..255".to_owned())?;
    Ok(IpTunnellingUserBinding { user_id, address_index })
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    match &args.command {
        Command::Init => return run_init(&args.project),
        Command::ImportProduct { product } => return run_import_product(&args.project, product),
        Command::Add { device, product, address, serial, fdsk, max_apdu, data_secure, topology, catalog_item } => {
            return run_add(
                &args.project,
                device,
                product,
                *address,
                *serial,
                fdsk.as_deref(),
                *max_apdu,
                *data_secure,
                topology,
                catalog_item.as_deref(),
            );
        }
        _ => {}
    }
    let store = ProjectStore::open(&args.project)
        .with_context(|| format!("while attempting to open {}", args.project.display()))?;

    match args.command {
        Command::Init | Command::ImportProduct { .. } | Command::Add { .. } => {
            unreachable!("authoring commands return before opening the project")
        }
        Command::Status => print_status(&store, args.master_data.as_deref(), &args.security),
        Command::ImportKeyring => run_import_keyring(store, &args.security),
        Command::ExportKeyring { out, name } => run_export_keyring(&store, &args.security, &out, name.as_deref()),
        Command::Check => run_check(&store, args.master_data.as_deref(), &args.security),
        Command::Address { device, all, dry_run, program_ia, programming_mode_timeout, device_mask } => {
            let device_mask = device_mask.as_deref().map(parse_mask).transpose()?;
            run_programming(
                store,
                args.master_data.as_deref(),
                &args.target,
                &args.security,
                device,
                false,
                all,
                dry_run,
                false,
                program_ia,
                programming_mode_timeout,
                device_mask,
                None,
                ProgrammingOperation::Address,
            )
            .await
        }
        Command::Load { device, affected, dry_run, full, device_mask, dump_blobs } => {
            let device_mask = device_mask.as_deref().map(parse_mask).transpose()?;
            run_programming(
                store,
                args.master_data.as_deref(),
                &args.target,
                &args.security,
                device,
                affected,
                false,
                dry_run,
                full,
                false,
                None,
                device_mask,
                dump_blobs.as_deref(),
                ProgrammingOperation::Load,
            )
            .await
        }
        Command::Program {
            device,
            affected,
            dry_run,
            full,
            program_ia,
            programming_mode_timeout,
            device_mask,
            dump_blobs,
        } => {
            let device_mask = device_mask.as_deref().map(parse_mask).transpose()?;
            run_programming(
                store,
                args.master_data.as_deref(),
                &args.target,
                &args.security,
                device,
                affected,
                false,
                dry_run,
                full,
                program_ia,
                programming_mode_timeout,
                device_mask,
                dump_blobs.as_deref(),
                ProgrammingOperation::Program,
            )
            .await
        }
        Command::Read { device, out } => {
            run_read(store, args.master_data.as_deref(), &args.target, &args.security, &device, &out).await
        }
        Command::Unload { device, all, application } => {
            let mode = cli_unload_mode(application, all)?;
            run_unload(store, args.master_data.as_deref(), &args.target, &args.security, &device, mode).await
        }
        Command::Sync => run_sync(store, args.master_data.as_deref(), &args.target, &args.security, false, None).await,
        Command::RecoverState { client_floor } => {
            run_sync(store, args.master_data.as_deref(), &args.target, &args.security, true, client_floor).await
        }
    }
}

fn run_init(project_path: &Path) -> Result<()> {
    if !project_path.exists() {
        let parent = project_path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("while attempting to create project directory {}", parent.display()))?;
        ProjectStore::write_authored(project_path, None, "# KNX project generated by `knx-loader init`\n")
            .with_context(|| format!("while attempting to create {}", project_path.display()))?;
    }

    let store = ProjectStore::open(project_path)
        .with_context(|| format!("while attempting to open {}", project_path.display()))?;
    match (store.keys().is_some(), store.state().is_some()) {
        (false, false) => {
            store.initialize().context("while attempting to initialize project keys and state")?;
        }
        (true, true) => {
            println!("project is already initialized: {}", project_path.display());
            return Ok(());
        }
        _ => bail!("project keys/state are only partially initialized; use recover-state rather than init"),
    }
    println!("initialized project: {}", project_path.display());
    Ok(())
}

fn run_import_product(project_path: &Path, product_path: &Path) -> Result<()> {
    // Import is also the first step of migrating a project from the removed
    // loose-MTXML syntax.  Deriving the immutable store from the authored file
    // path keeps that operation available even while the old project text no
    // longer parses; no project values are needed to index and retain a
    // package.
    let metadata = fs::metadata(project_path).with_context(|| {
        format!("while attempting to locate {}; run `knx-loader --project ... init` first", project_path.display())
    })?;
    if !metadata.is_file() {
        bail!("{} is not a project file", project_path.display());
    }
    let canonical_product = product_path
        .canonicalize()
        .with_context(|| format!("while attempting to locate product {}", product_path.display()))?;
    require_knxprod_path(&canonical_product)?;
    let package_store = PackageStore::new(package_store_directory_for_project(project_path));
    let imported = package_store
        .import(&canonical_product)
        .with_context(|| format!("while attempting to index and import {}", canonical_product.display()))?;

    print_package_summary(&imported.package, imported.already_present);
    for notice in &imported.notices {
        eprintln!("notice: {notice}");
    }
    Ok(())
}

fn package_store_directory_for_project(project_path: &Path) -> PathBuf {
    project_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join(".zweidraehte/packages")
}

fn project_package_store(store: &ProjectStore) -> Result<PackageStore> {
    let root = store
        .authored()
        .package_store_directory()
        .context("project source has no filesystem path for its package store")?;
    Ok(PackageStore::new(root))
}

fn require_knxprod_path(path: &Path) -> Result<()> {
    if !path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("knxprod")) {
        bail!("{} is not a .knxprod package; project devices require the complete product archive", path.display());
    }
    Ok(())
}

fn print_package_summary(package: &StoredPackage, already_present: bool) {
    println!(
        "{} package {} ({} catalogue item{})",
        if already_present { "existing" } else { "imported" },
        package.digest(),
        package.leaves().count(),
        if package.leaves().count() == 1 { "" } else { "s" },
    );
    let mut leaves = package.leaves().collect::<Vec<_>>();
    leaves.sort_by(|left, right| left.selector.catalog_item_id.cmp(&right.selector.catalog_item_id));
    if leaves.is_empty() {
        println!("  no CatalogItem leaves; the package is retained but cannot instantiate a project device");
    }
    for leaf in leaves {
        println!("  {}", catalog_leaf_label(leaf));
    }
}

fn select_catalog_leaf(package: &StoredPackage, catalog_item: Option<&str>) -> Result<PackageCatalogLeaf> {
    let leaves = package.leaves().cloned().collect::<Vec<_>>();
    if let Some(catalog_item) = catalog_item {
        let leaf = leaves
            .into_iter()
            .find(|leaf| leaf.selector.catalog_item_id == catalog_item)
            .with_context(|| format!("package {} has no CatalogItem {catalog_item:?}", package.digest()))?;
        ensure_instantiable(&leaf)?;
        return Ok(leaf);
    }

    let instantiable = leaves.into_iter().filter(|leaf| leaf.instantiable).collect::<Vec<_>>();
    match instantiable.as_slice() {
        [] => bail!(
            "package {} has no instantiable CatalogItem; use `import-product` to retain a catalogue-less package",
            package.digest()
        ),
        [leaf] => Ok(leaf.clone()),
        _ => {
            let labels = instantiable.iter().map(catalog_leaf_label).collect::<Vec<_>>();
            let selected = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Select the KNX catalogue item to add")
                .items(&labels)
                .default(0)
                .interact_opt()
                .context("while attempting to show the catalogue selection dialog")?
                .context("catalogue selection cancelled; pass --catalog-item to select non-interactively")?;
            Ok(instantiable[selected].clone())
        }
    }
}

fn ensure_instantiable(leaf: &PackageCatalogLeaf) -> Result<()> {
    if leaf.instantiable {
        return Ok(());
    }
    bail!(
        "CatalogItem {:?} is not instantiable ({}): registration {}",
        leaf.selector.catalog_item_id,
        instantiation_label(leaf.instantiation),
        registration_label(leaf),
    )
}

fn catalog_leaf_label(leaf: &PackageCatalogLeaf) -> String {
    format!(
        "{} [{}] — {:?} — {} — registration: {}{}",
        leaf.name,
        leaf.order_number,
        leaf.selector.catalog_item_id,
        leaf.application_program_id().unwrap_or("no application program"),
        registration_label(leaf),
        if leaf.instantiable { "" } else { " — not instantiable" },
    )
}

fn instantiation_label(instantiation: PackageInstantiation) -> &'static str {
    match instantiation {
        PackageInstantiation::Programmable => "programmable",
        PackageInstantiation::CatalogOnly(PackageCatalogOnlyReason::NoApplicationProgram) => {
            "hardware declares no application program"
        }
        PackageInstantiation::Blocked(PackageInstantiationBlock::RegistrationStatus(_)) => {
            "registration status is blocked"
        }
    }
}

fn registration_label(leaf: &PackageCatalogLeaf) -> String {
    let registration = &leaf.effective_registration;
    let mut label = registration.status.to_string();
    if let Some(number) = &registration.registration_number {
        label.push_str(&format!(" · no. {number}"));
    }
    if let Some(date) = &registration.registration_date {
        label.push_str(&format!(" · {date}"));
    }
    label
}

fn validate_catalog_medium(leaf: &PackageCatalogLeaf, medium: Medium) -> Result<()> {
    let required = match medium {
        Medium::Tp1 => "MT-0",
        Medium::Rf => "MT-2",
        Medium::Ip => "MT-5",
    };
    if leaf.medium_types.split_whitespace().any(|candidate| candidate == required) {
        return Ok(());
    }
    bail!(
        "CatalogItem {:?} declares H2P MediumTypes={:?}, which is incompatible with the authored {:?} line ({required})",
        leaf.selector.catalog_item_id,
        leaf.medium_types,
        medium,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_add(
    project_path: &Path,
    device: &str,
    product_path: &Path,
    address: zweidraehte_client::IndividualAddress,
    serial: Option<[u8; 6]>,
    fdsk: Option<&str>,
    max_apdu: Option<u16>,
    data_secure: bool,
    topology: &AddTopologyArgs,
    catalog_item: Option<&str>,
) -> Result<()> {
    let store = ProjectStore::open(project_path).with_context(|| {
        format!("while attempting to open {}; run `knx-loader --project ... init` first", project_path.display())
    })?;
    let canonical_product = product_path
        .canonicalize()
        .with_context(|| format!("while attempting to locate product {}", product_path.display()))?;
    require_knxprod_path(&canonical_product)?;
    let package_store = project_package_store(&store)?;
    let imported = package_store
        .import(&canonical_product)
        .with_context(|| format!("while attempting to index and import {}", canonical_product.display()))?;
    for notice in &imported.notices {
        eprintln!("notice: {notice}");
    }
    let leaf = select_catalog_leaf(&imported.package, catalog_item)?;
    let selected_product = ProjectProduct::load(&package_store, &leaf.selector)
        .context("while attempting to load the selected package catalogue item")?;

    if data_secure && !selected_product.program().is_secure_enabled.unwrap_or(false) {
        bail!("application `{}` does not declare Data Secure support", selected_product.program().id);
    }

    // A KNX device certificate is the Base32 spelling of
    // `serial || FDSK || CRC`. Reconcile the embedded serial before changing
    // either project.knx or keys.toml, and reject key conflicts up front.
    let decoded_fdsk =
        fdsk.map(parse_fdsk).transpose().context("while attempting to parse the FDSK or device certificate")?;
    let serial = reconcile_certificate_serial(serial, decoded_fdsk.as_ref())?;
    if let Some(decoded) = &decoded_fdsk {
        let keys = store.keys().context("project keys are not initialized; run `knx-loader --project ... init`")?;
        let id = KeyId { scope: KeyScope::Device(device.to_string()), kind: KeyKind::Fdsk };
        if let Some(existing) = keys.read(&id, None).context("while attempting to check the existing device FDSK")? {
            if existing.value.key16().context("while attempting to decode the existing device FDSK")? != *decoded.key()
            {
                bail!("a different FDSK is already stored for device `{device}`");
            }
            if let (Some(project_serial), Some(stored_serial)) = (serial, existing.embedded_serial)
                && project_serial != stored_serial
            {
                bail!(
                    "stored FDSK serial {} disagrees with device serial {}",
                    format_serial(&stored_serial),
                    format_serial(&project_serial)
                );
            }
        }
    }

    let topology = topology.to_draft(address)?;
    validate_catalog_medium(&leaf, topology.medium)?;
    if topology.medium == Medium::Ip {
        validate_ip_configuration_ownership(
            &topology,
            &selected_product.product().programming_options().ip_configuration().value,
        )?;
    }
    let draft = ProjectDeviceDraft {
        id: ProjectDeviceId(device.to_string()),
        active: true,
        product: ProductReference::Package {
            package: ProjectPackageId::from_bytes(*leaf.selector.package.as_bytes()),
            catalog_item: leaf.selector.catalog_item_id.clone(),
        },
        address,
        medium: topology.medium,
        domain: topology.domain,
        ip_line: topology.ip_line,
        rf_mode: topology.rf_mode,
        ip: topology.ip,
        routing: topology.routing,
        serial,
        max_apdu,
        data_secure: if data_secure { DataSecureMode::Enabled } else { DataSecureMode::Disabled },
        parameters: Vec::new(),
        objects: BTreeMap::new(),
        nets: BTreeMap::new(),
    };
    let source =
        store.authored().render_device_add(&draft).context("while attempting to add the device declaration")?;
    let checked = zweidraehte_project::AuthoredProject::parse(source.clone())
        .context("while attempting to parse the updated project")?;
    checked.validate_download().map_err(|error| {
        anyhow::anyhow!(
            "{}",
            error.diagnostics().iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join("; ")
        )
    })?;
    // Acquire after interactive selection, then keep credentials and source
    // under one writer. A stale project must fail before the FDSK is stored.
    let expected = store.authored().source().to_string();
    let mut writer = store.into_writer().context("while attempting to acquire the project writer")?;
    if let (Some(encoded), Some(decoded)) = (fdsk, decoded_fdsk) {
        let origin = if decoded.serial.is_some() { KeyOrigin::DeviceLabel } else { KeyOrigin::Manual };
        writer
            .update_authored_with_keys(&expected, source, |keys| keys.put_device_fdsk(device, encoded, origin))
            .context("while attempting to persist the device FDSK and updated project")?;
    } else {
        writer.update_authored(source).context("while attempting to persist the updated project")?;
    }

    println!(
        "added {device} at {address} from package {}, catalogue item {:?}, application {}{}{}",
        leaf.selector.package,
        leaf.selector.catalog_item_id,
        selected_product.program().id,
        serial.as_ref().map_or_else(String::new, |serial| format!(", serial {}", format_serial(serial))),
        fdsk.map_or("", |_| ", FDSK stored")
    );
    Ok(())
}

fn reconcile_certificate_serial(configured: Option<[u8; 6]>, fdsk: Option<&DecodedFdsk>) -> Result<Option<[u8; 6]>> {
    let embedded = fdsk.and_then(|fdsk| fdsk.serial);
    if let (Some(configured), Some(embedded)) = (configured, embedded)
        && configured != embedded
    {
        bail!(
            "device certificate serial {} disagrees with --serial {}",
            format_serial(&embedded),
            format_serial(&configured)
        );
    }
    Ok(configured.or(embedded))
}

fn parse_project_serial(value: &str) -> Result<[u8; 6], String> {
    parse_serial(value).map_err(|error| error.to_string())
}

fn print_status(store: &ProjectStore, master_data: Option<&Path>, security: &SecurityArgs) -> Result<()> {
    let inputs = load_status_inputs(store, master_data, security).context("acquire programming status inputs")?;
    let snapshot = inputs.snapshot().context("compile programming status")?;
    let store = inputs.store();
    let products = inputs.products();
    let view = snapshot.view();
    for id in store.authored().devices.keys() {
        let desired = &store.authored().devices[id];
        if !desired.active {
            println!("{id}: inactive, Data Secure not evaluated");
            continue;
        }

        let supports_data_secure = products[id].product().supports_data_secure();
        let programming = view.statuses[id];
        let status = if programming.is_complete() {
            "current".to_string()
        } else {
            format!("affected ({})", changed_programming_components(programming).join(", "))
        };
        let inconsistent =
            store.state().is_some_and(|state| state.inconsistent_devices.iter().any(|candidate| candidate == &id.0));
        let data_secure = match (supports_data_secure, desired.data_secure.is_enabled()) {
            (false, false) => "unsupported",
            (false, true) => "invalid: enabled but unsupported",
            (true, false) => "supported, disabled",
            (true, true) => "supported, enabled",
        };
        println!("{id}: {status}, Data Secure {data_secure}{}", if inconsistent { ", inconsistent batch" } else { "" });
    }
    match (store.keys(), store.state()) {
        (None, None) => println!("project state: not initialized"),
        (Some(_), Some(state)) if state.recovery_required => {
            println!("project state: recovery required; secure group sending is blocked")
        }
        (Some(_), Some(_)) if !store.secure_state_ready() => {
            println!("project state: identity mismatch; run recover-state")
        }
        (Some(_), Some(state)) => println!("project state: ready, next client sequence {}", state.client_next),
        _ => println!("project state: partially initialized; run recover-state"),
    }
    Ok(())
}

fn load_status_inputs(
    store: &ProjectStore,
    master_data: Option<&Path>,
    security: &SecurityArgs,
) -> Result<ProjectStatusInputs> {
    ProjectStatusInputs::load(
        ProjectStatusRequest {
            project_path: store.project_path(),
            draft: None,
            scope: None,
            master_data,
            keyring_path: security.keyring_path(),
        },
        &mut ProjectStatusCache::default(),
        || security.load_keyring().map_err(Into::into),
        |_, _, _| {},
    )
    .context("load coherent project inputs")
}

fn changed_programming_components(status: zweidraehte_project::DeviceProgrammingStatus) -> Vec<&'static str> {
    [
        (!status.individual_address, "Adr"),
        (!status.application_program, "Prg"),
        (!status.parameters, "Par"),
        (!status.group_communication, "Grp"),
        (!status.medium_configuration, "Cfg"),
    ]
    .into_iter()
    .filter_map(|(changed, label)| changed.then_some(label))
    .collect()
}

fn run_check(store: &ProjectStore, master_data: Option<&Path>, security: &SecurityArgs) -> Result<()> {
    let inputs = load_status_inputs(store, master_data, security).context("acquire project validation inputs")?;
    let intent = CommissioningIntent::Download(DownloadMode::Full);
    let plan = inputs
        .planner()
        .plan_commissioning(&[], BatchSelection::All, intent)
        .context("validate and lower the project")?;
    if plan.devices().is_empty() {
        println!("0 devices validated and compiled");
        return Ok(());
    }

    for device in plan.devices() {
        compile_offline(
            device,
            inputs
                .catalogs()
                .for_product(device.device().product())
                .context("while attempting to select product Master Data")?,
            intent,
            None,
        )
        .context("compile project device")?;
        for warning in device.warnings() {
            eprintln!("warning: {warning}");
        }
    }
    inputs.verify_unchanged().context("verify project validation inputs")?;
    println!("{} devices validated and compiled", plan.devices().len());
    Ok(())
}

// ============================================================================
// Explicit ETS keyring import
// ============================================================================

fn run_import_keyring(store: ProjectStore, security: &SecurityArgs) -> Result<()> {
    let keyring = security
        .load_keyring()
        .context("while attempting to load the ETS keyring")?
        .context("give --keyring and its password to import-keyring")?;
    let session =
        ProjectCommissioningSession::begin(store).context("while attempting to acquire the project writer")?;
    let plan = session.plan_keyring_import(&keyring).context("while attempting to reconcile the ETS keyring")?;
    let summary = plan.apply().context("while attempting to apply the ETS keyring import")?;
    println!(
        "imported or reconciled {} devices and {} group keys; ignored {} unrelated devices and {} unrelated group keys",
        summary.matched_devices, summary.matched_groups, summary.ignored_devices, summary.ignored_groups
    );
    Ok(())
}

fn run_export_keyring(
    store: &ProjectStore,
    security: &SecurityArgs,
    output: &Path,
    project_name: Option<&str>,
) -> Result<()> {
    let keys = store.keys().context("project keys are not initialized; run `knx-loader --project ... init`")?;
    let state = store.state().context("project state is not initialized; run `knx-loader --project ... init`")?;
    let password = security
        .keyring_password()
        .context("give --keyring-password or KNX_KEYRING_PASSWORD to protect the exported keyring")?;
    let default_name = store
        .project_path()
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("zweidraehte project");
    let created = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .context("while attempting to round the keyring creation time")?
        .format(&time::format_description::well_known::Rfc3339)
        .context("while attempting to format the keyring creation time")?;
    let keyring = build_project_keyring(
        store.authored(),
        state,
        keys,
        project_name.unwrap_or(default_name),
        concat!("zweidraehte knx-loader ", env!("CARGO_PKG_VERSION")),
        created,
    )
    .context("while attempting to collect project keyring material")?;
    let device_count = keyring.devices.len();
    let group_count = keyring.group_key_count();
    let xml = keyring.to_xml(&password).context("while attempting to encrypt and sign the ETS keyring")?;
    write_new_secret_file(output, xml.as_bytes())
        .with_context(|| format!("while attempting to create keyring {}", output.display()))?;

    println!(
        "exported {device_count} device entries and {group_count} active group keys to {}; client sequence {} remains project-local",
        output.display(),
        state.client_next
    );
    Ok(())
}

fn write_new_secret_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    File::open(parent)?.sync_all()
}

#[allow(clippy::too_many_arguments)]
async fn run_programming(
    store: ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    device: Option<String>,
    affected: bool,
    all: bool,
    dry_run: bool,
    force_full: bool,
    program_ia: bool,
    programming_mode_timeout: Option<u64>,
    device_mask: Option<MaskVersion>,
    dump_blobs: Option<&Path>,
    operation: ProgrammingOperation,
) -> Result<()> {
    let (selected, selection) = programming_selection(device, affected, all, operation)
        .context("while attempting to select the programming scope")?;
    let requested_intent = operation.requested_intent(force_full);
    let mut inputs = ProjectOperationInputs::load(
        store,
        ProjectInputRequest {
            selected: &selected,
            selection,
            intent: requested_intent,
            sources: ProjectInputSources { master_data, keyring_path: security.keyring_path() },
        },
        || security.load_keyring().map_err(Into::into),
    )
    .context("while attempting to acquire project programming inputs")?;
    let mut plan = inputs.plan().context("while attempting to plan the commissioning batch")?;
    ensure_single_programming_button_target(&plan, program_ia)
        .context("while attempting to validate programming-button selection")?;
    if plan.devices().is_empty() {
        println!("no affected devices");
        return Ok(());
    }
    plan.configure(Default::default(), true, DifferentialPolicy::FallBackToUndifferenced);
    configure_programming_button_target(&mut plan, program_ia, programming_mode_timeout)
        .context("while attempting to configure programming-button discovery")?;
    let requirements = inputs.requirements(&plan);
    if operation == ProgrammingOperation::Load
        && let Some(ProjectSetupRequirement::GenerateToolKey { device }) = requirements
            .iter()
            .find(|requirement| matches!(requirement, ProjectSetupRequirement::GenerateToolKey { .. }))
    {
        bail!("device `{device}` has no Tool Key; run `knx-loader ... address {device}` or `program {device}` first");
    }
    for planned in plan.devices() {
        for warning in planned.warnings() {
            eprintln!("warning: {warning}");
        }
    }

    if dry_run {
        for planned in plan.devices() {
            let intent = planned.commissioning().intent;
            if operation.includes_application() {
                let compiled = compile_offline(
                    planned,
                    inputs
                        .programming_inputs()
                        .catalogs
                        .for_product(planned.device().product())
                        .context("while attempting to select product Master Data")?,
                    intent,
                    device_mask,
                )
                .context("while attempting to compile the device offline")?;
                print_compiled(planned, &compiled);
                dump_blob_files(dump_blobs, &planned.id().0, &compiled)
                    .context("while attempting to export compiled memory blobs")?;
            } else {
                println!("{}: would commission {}", planned.id(), planned.device().configuration().individual_address);
            }

            if planned.needs_tool_key_generation() {
                println!("{}: would generate and persist a tool key before bus access", planned.id());
            }
        }
        inputs.verify_unchanged().context("while attempting to verify dry-run inputs")?;
        println!("dry run: {} planned devices", plan.devices().len());
        return Ok(());
    }

    match inputs.state_requirement() {
        Some(ProjectSetupRequirement::InitializeProject) => {
            inputs.initialize().context("while attempting to initialize project keys and state")?;
        }
        Some(requirement) => {
            return Err(ClientError::from(requirement)).context("while attempting to prepare project state");
        }
        None => {}
    }
    let target = require_target(target).context("while attempting to select the bus interface")?;
    let session = inputs.begin_session().context("while attempting to open the project commissioning session")?;

    let cancellation = CommissioningCancellation::default();
    let mut progress = |device: &ProjectDeviceId, event| print_commissioning_progress(Some(device), event);
    let execution = ProjectOperationRequest::new(plan).generate_missing_tool_keys().execute(session, |security| target.connect_with_security(security), inputs.programming_inputs(), &cancellation, &mut progress, |device| {
        let commissioning = device.commissioning();
        let profile = commissioning.plan().profile();
        if let Some(expected) = device_mask && profile.mask().dd0 != expected.as_u16() {
            return Err(ClientError::DeviceConfiguration(format!(
                "{} resolved live DD0 {:04X}, not requested --device-mask {:04X}",
                device.id(), profile.mask().dd0, expected.as_u16(),
            )));
        }
        let fallback = match commissioning.differential() {
            DifferentialDecision::FellBackToUndifferenced { reason } => Some(*reason),
            DifferentialDecision::VerifiedUndifferenced { .. } => Some(DifferentialFallback::NoUsefulDifference),
            _ => None,
        };
        if let Some(reason) = fallback {
            eprintln!("warning: {} cannot use a sparse difference ({reason:?}); using the undifferenced selected scope", device.id());
        }
        let steps = commissioning.plan().procedure().map_or(0, |procedure| procedure.steps.len());
        println!("preflight {}: current {}, profile {}, sections {:?}, {steps} steps", device.id(),
            commissioning.discovered_device().address.map_or_else(|| "unknown".to_owned(), |address| address.to_string()),
            profile.mask(), commissioning.plan().program_sections());
        Ok(())
    }).await;

    let reports = execution.map_err(|error| {
        if operation == ProgrammingOperation::Load && selected.len() == 1 && is_management_access_preflight_error(&error) {
            let device = &selected[0];
            anyhow::Error::new(error).context(format!(
                "preflight application-only `load` for `{device}`; `load` never assigns an IA, so use `program {device} --program-ia` when its IA was unloaded"
            ))
        } else { anyhow::Error::new(error) }
    }).context("execute the project programming queue")?;
    for completed in &reports.devices {
        let report = &completed.report;
        println!(
            "{}: {} at {}, mask {}{}",
            completed.id,
            operation_completed(operation),
            report.plan.individual_address(),
            report.plan.profile().mask(),
            if let Some(procedure) = &report.procedure {
                format!(", {} steps", procedure.steps_completed)
            } else {
                String::new()
            }
        );
    }
    println!("{} {} devices", operation_completed(operation), reports.devices.len());
    Ok(())
}

fn programming_selection(
    device: Option<String>,
    affected: bool,
    all: bool,
    operation: ProgrammingOperation,
) -> Result<(Vec<ProjectDeviceId>, BatchSelection)> {
    if let Some(device) = device {
        if all {
            bail!("a device identifier cannot be combined with --all");
        }
        if affected {
            bail!("--affected is project-wide; omit the device identifier");
        }

        return Ok((vec![ProjectDeviceId(device)], BatchSelection::Selected));
    }
    if all {
        return Ok((
            Vec::new(),
            if operation == ProgrammingOperation::Address { BatchSelection::All } else { BatchSelection::AllStale },
        ));
    }
    if !affected {
        bail!("give a device identifier or use --affected");
    }
    Ok((Vec::new(), BatchSelection::AllStale))
}

fn ensure_single_programming_button_target(plan: &ProgrammingBatchPlan, program_ia: bool) -> Result<()> {
    if !program_ia {
        return Ok(());
    }

    let address_targets = plan.devices().iter().filter(|device| plan.impact().selected.contains(&device.id())).count();
    if address_targets != 1 {
        bail!("physical programming mode requires exactly one selected device");
    }

    Ok(())
}

fn configure_programming_button_target(
    plan: &mut ProgrammingBatchPlan,
    program_ia: bool,
    timeout: Option<u64>,
) -> Result<()> {
    if !program_ia {
        return Ok(());
    }

    let planned = plan
        .devices()
        .iter()
        .find(|device| plan.impact().selected.contains(&device.id()))
        .context("programming-button target is not part of the plan")?;
    let id = planned.id().clone();
    let mut polling = ProgrammingModePolling::default();
    polling.timeout = timeout.map_or(DEFAULT_PROGRAMMING_MODE_TIMEOUT, Duration::from_secs);

    plan.set_target(&id, TargetSelection::ProgrammingButton(polling))
        .context("select the programming-button target")?;

    Ok(())
}

fn is_management_access_preflight_error(error: &ClientError) -> bool {
    let error = match error {
        ClientError::ProjectBatch(failure) => match failure.source.as_deref() {
            Some(source) => source,
            None => return false,
        },
        error => error,
    };
    let ClientError::Commissioning(source) = error else {
        return false;
    };

    let diagnostic = source.diagnostic();
    diagnostic.kind() == zweidraehte_client::commissioning::DiagnosticKind::Preparation
        && (diagnostic.message().contains("management access")
            || diagnostic.message().contains("management credential"))
}

fn cli_unload_mode(application: bool, all: bool) -> Result<UnloadMode> {
    match (application, all) {
        (true, false) => Ok(UnloadMode::Application),
        (false, true) => Ok(UnloadMode::AllConfiguration),
        _ => bail!("select exactly one unload scope: --application or --all"),
    }
}

fn operation_completed(operation: ProgrammingOperation) -> &'static str {
    match operation {
        ProgrammingOperation::Address => "commissioned",
        ProgrammingOperation::Load => "loaded",
        ProgrammingOperation::Program => "programmed",
    }
}

async fn run_read(
    store: ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    device_id: &str,
    out: &Path,
) -> Result<()> {
    let keyring = security.load_keyring().context("while attempting to load the ETS keyring")?;
    let target = require_target(target).context("while attempting to select the bus interface")?;
    let session = ProjectCommissioningSession::begin(store).context("while attempting to open the project session")?;
    let operation =
        ProjectOperation::connect(session, keyring.as_ref(), |security| target.connect_with_security(security))
            .await
            .context("while attempting to open the project operation")?;
    let result =
        operation.read_device_memory(&ProjectDeviceId(device_id.into()), keyring.as_ref(), master_data, true).await;

    let report = match &result {
        Ok(report) => report,
        Err(failure) => &failure.report,
    };
    if let Some(access) = report.access {
        println!("access: {access:?}");
    }
    // Preserve completed blobs even if a later segment failed. File errors
    // happen after bus finalization and must not replace the read failure.
    let export = (|| -> Result<()> {
        if !report.segments.is_empty() {
            std::fs::create_dir_all(out).with_context(|| format!("while attempting to create {}", out.display()))?;
        }
        for segment in &report.segments {
            let path = out.join(format!("region_{:04X}.bin", segment.address));
            std::fs::write(&path, &segment.bytes)
                .with_context(|| format!("while attempting to write {}", path.display()))?;
        }
        Ok(())
    })();
    match (result, export) {
        (Err(read), Err(export)) => Err(anyhow::Error::new(read).context(export)),
        (Err(read), _) => Err(anyhow::Error::new(read)),
        (_, Err(export)) => Err(export),
        _ => Ok(()),
    }
    .context("while attempting to inspect device memory")
}

async fn run_unload(
    store: ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    device_id: &str,
    mode: UnloadMode,
) -> Result<()> {
    let selected = [ProjectDeviceId(device_id.to_string())];
    let inputs = ProjectOperationInputs::load(
        store,
        ProjectInputRequest {
            selected: &selected,
            selection: BatchSelection::Selected,
            intent: CommissioningIntent::Unload(mode),
            sources: ProjectInputSources { master_data, keyring_path: security.keyring_path() },
        },
        || security.load_keyring().map_err(Into::into),
    )
    .context("while attempting to acquire project unload inputs")?;
    let mut plan = inputs.plan().context("while attempting to plan the unload")?;
    plan.configure(Default::default(), true, DifferentialPolicy::Disabled);
    let target = require_target(target).context("while attempting to select the bus interface")?;
    let session = inputs.begin_session().context("while attempting to open the project commissioning session")?;
    let cancellation = CommissioningCancellation::default();
    let mut progress = |device: &ProjectDeviceId, event| print_commissioning_progress(Some(device), event);
    ProjectOperationRequest::new(plan)
        .execute(
            session,
            |security| target.connect_with_security(security),
            inputs.programming_inputs(),
            &cancellation,
            &mut progress,
            |_| Ok(()),
        )
        .await
        .context("while attempting to unload the device")?;

    println!("unloaded {} from `{device_id}`", match mode {
        UnloadMode::Application => "application",
        UnloadMode::AllConfiguration => "all configuration",
    });

    Ok(())
}

async fn run_sync(
    store: ProjectStore,
    master_data: Option<&Path>,
    target: &OptionalTargetArgs,
    security: &SecurityArgs,
    recover: bool,
    client_floor: Option<u64>,
) -> Result<()> {
    let keyring = security.load_keyring().context("while attempting to load the ETS keyring")?;
    let target = require_target(target).context("while attempting to select the bus interface")?;
    let session = if recover {
        ProjectCommissioningSession::begin_recovery(store)
    } else {
        ProjectCommissioningSession::begin(store)
    }
    .context("while attempting to open the project session")?;
    let operation =
        ProjectOperation::connect(session, keyring.as_ref(), |security| target.connect_with_security(security))
            .await
            .context("while attempting to open the project operation")?;
    let mode =
        if recover { ProjectSynchronization::Recover { client_floor } } else { ProjectSynchronization::Synchronize };
    let result = operation.synchronize(keyring.as_ref(), master_data, mode).await;
    let report = match &result {
        Ok(report) => report,
        Err(failure) => &failure.report,
    };
    for device in &report.devices {
        if let Some(error) = &device.unavailable {
            eprintln!("{}: unavailable ({error})", device.device);
        } else if device.complete {
            println!("{}: synchronised", device.device);
        } else {
            eprintln!("{}: synchronization interrupted", device.device);
        }
    }
    result.map(|_| ()).context("while attempting to synchronize project state")
}

fn compile_offline(
    planned: &PlannedProjectDevice,
    catalog: zweidraehte_client::commissioning::ProgrammingCatalog,
    intent: CommissioningIntent,
    device_mask: Option<MaskVersion>,
) -> Result<zweidraehte_client::commissioning::CompiledProgram> {
    let product_mask = planned.device().product().mask_version().context("product has no mask version")?;
    let profile = catalog
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery {
                dd0: device_mask.unwrap_or(product_mask).as_u16(),
                management_descriptor_01: None,
                management_style: None,
            },
            product: Some(planned.device().product()),
            variant_hint: VariantHint::Automatic,
        })
        .context("while attempting to resolve the exact offline programming profile")?;
    let automatic_sections = matches!(
        intent,
        CommissioningIntent::Download(DownloadMode::Automatic)
            | CommissioningIntent::AssignAddressAndDownload(DownloadMode::Automatic)
    )
    .then(|| planned.automatic_program_sections());
    // An offline preview selects a credential scenario from the available
    // keys. Live preparation independently authenticates the actual target.
    // Desired application security never determines management access.
    let keys = planned.device().key_material();
    let credential = if keys.tool_key().is_some() {
        ManagementCredential::ToolKey
    } else if keys.fdsk().is_some() {
        ManagementCredential::Fdsk
    } else {
        ManagementCredential::Plaintext
    };
    let facts = ProgrammingFacts::new(ObservedTarget {
        previous_address: planned.device().configuration().individual_address,
        serial_number: planned.serial_number(),
        credential,
    })
    .with_data_security(planned.observed_data_security());

    let options = CompileOptions {
        target: TargetSelection::ExistingAddress(planned.device().configuration().individual_address),
        automatic_sections,
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
    };

    let plan = planned
        .compile_preview(
            zweidraehte_client::commissioning::ProfileSelection::new(ProfileDiscovery {
                dd0: profile.mask().dd0,
                management_descriptor_01: profile.mask().management_descriptor_01,
                management_style: profile.management_style(),
            })
            .with_variant(profile.variant().legacy_version.map_or(VariantHint::Automatic, VariantHint::LegacyVersion)),
            intent,
            options,
            facts,
        )
        .context("while attempting to compile the commissioning plan")?;
    Ok(plan)
}

fn print_compiled(planned: &PlannedProjectDevice, compiled: &zweidraehte_client::commissioning::CompiledProgram) {
    let steps = compiled.procedure().map_or(0, |procedure| procedure.steps.len());
    let transfer_bytes: u64 = compiled
        .procedure()
        .into_iter()
        .flat_map(|procedure| &procedure.steps)
        .filter_map(|step| match &step.operation {
            zweidraehte_client::commissioning::inspection::ProcedureOperation::Write { extent, .. } => {
                Some(u64::from(extent.byte_length))
            }
            _ => None,
        })
        .sum();
    let stamp_reads = compiled
        .procedure()
        .into_iter()
        .flat_map(|procedure| &procedure.steps)
        .filter(|step| {
            matches!(
                &step.operation,
                zweidraehte_client::commissioning::inspection::ProcedureOperation::ReadIntoImage {
                    capture_as: Some(_),
                    ..
                }
            )
        })
        .count();
    let procedure = compiled.procedure().map_or_else(|| "none".to_owned(), |procedure| format!("{:?}", procedure.id));
    println!(
        "{}: {}, profile {}, procedure {procedure}, sections {:?}, {} parameters, {} associations, {steps} steps, \
         {transfer_bytes} transfer bytes",
        planned.id(),
        planned.device().configuration().individual_address,
        compiled.profile().mask(),
        compiled.program_sections(),
        planned.device().configuration().parameters.len(),
        planned.device().configuration().links.len(),
    );
    if stamp_reads > 0 {
        println!("  captures {stamp_reads} download stamps before restart");
    }
    for segment in compiled.image().segments() {
        println!(
            "  {:?} at {:#08X}: {} bytes",
            segment.location().space,
            segment.location().offset,
            segment.data().len()
        );
    }
}

fn dump_blob_files(
    directory: Option<&Path>,
    device: &str,
    compiled: &zweidraehte_client::commissioning::CompiledProgram,
) -> Result<()> {
    let Some(directory) = directory else { return Ok(()) };
    let directory = directory.join(device);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("while attempting to create {}", directory.display()))?;
    for (index, segment) in compiled.image().segments().into_iter().enumerate() {
        let space = match &segment.location().space {
            ImageSpace::StandardMemory => "standard_memory",
            ImageSpace::UserMemory => "user_memory",
            ImageSpace::RelativeMemory { .. } => "relative_memory",
            ImageSpace::Property { .. } => "property",
            ImageSpace::PropertyCount { .. } => "property_count",
            ImageSpace::Pointer { .. } => "pointer",
            ImageSpace::LineCouplerFilter => "line_coupler_filter",
            ImageSpace::LineCouplerSlave => "line_coupler_slave",
        };
        let path = directory.join(format!("{index:03}_{space}_{:08X}.bin", segment.location().offset));
        std::fs::write(&path, segment.data())
            .with_context(|| format!("while attempting to write {}", path.display()))?;
    }
    Ok(())
}

fn print_commissioning_progress(device: Option<&ProjectDeviceId>, event: CommissioningEvent) {
    let prefix = device.map_or_else(String::new, |device| format!("{device}: "));

    match event {
        CommissioningEvent::Stage(stage) => println!("  {prefix}{}", commissioning_stage_name(stage)),
        CommissioningEvent::TargetDiscovered { address, serial_number } => {
            println!(
                "  {prefix}found {address}{}",
                serial_number.map_or_else(String::new, |serial| format!(" ({})", format_serial(&serial)))
            );
        }
        CommissioningEvent::AddressAssigned { previous, current, serial_number } => {
            println!(
                "  {prefix}assigned {current} (previous {previous}){}",
                serial_number.map_or_else(String::new, |serial| format!(" ({})", format_serial(&serial)))
            );
        }
        CommissioningEvent::ProgrammingSectionsMutated { .. } => {}
        CommissioningEvent::DifferentialFallback(reason) => {
            println!("  {prefix}sparse difference unavailable ({reason:?}); using the undifferenced selected scope");
        }
        CommissioningEvent::Step { index, total, description } => {
            println!("    {prefix}step {index}/{total}: {description}");
        }
        CommissioningEvent::Data { done, total } => println!("    {prefix}data {done}/{total}"),
        CommissioningEvent::ProgressText(message) => println!("    {prefix}{message}"),
    }
}

fn commissioning_stage_name(stage: CommissioningStage) -> &'static str {
    match stage {
        CommissioningStage::DiscoveringTarget => "discovering target",
        CommissioningStage::IdentifyingProfile => "identifying exact profile",
        CommissioningStage::CompilingPlan => "compiling plan",
        CommissioningStage::ValidatingDifferential => "validating differential evidence",
        CommissioningStage::AssigningAddress => "assigning individual address",
        CommissioningStage::BootstrappingSecurity => "bootstrapping security",
        CommissioningStage::ConfiguringNetwork => "configuring network",
        CommissioningStage::Verifying => "verifying",
        CommissioningStage::Connecting => "connecting",
        CommissioningStage::Executing => "executing procedure",
        CommissioningStage::RestoringDeviceState => "restoring device state",
        CommissioningStage::Disconnecting => "disconnecting",
        CommissioningStage::Complete => "complete",
    }
}

fn parse_mask(value: &str) -> Result<MaskVersion> {
    u16::from_str_radix(value.trim_start_matches("0x"), 16)
        .map(MaskVersion::from)
        .context("--device-mask wants a hexadecimal mask such as 0020")
}

fn require_target(target: &OptionalTargetArgs) -> Result<BusTarget> {
    target.to_target().context("give --server or --usb before the subcommand")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_import_location_does_not_require_parsing_project_source() {
        assert_eq!(
            package_store_directory_for_project(Path::new("bench/project.knx")),
            PathBuf::from("bench/.zweidraehte/packages")
        );
        assert_eq!(
            package_store_directory_for_project(Path::new("project.knx")),
            PathBuf::from("./.zweidraehte/packages")
        );
    }

    #[test]
    fn cli_authors_only_package_and_catalog_item_selectors() {
        let parsed = Args::try_parse_from([
            "knx-loader",
            "add",
            "button",
            "products.knxprod",
            "--address",
            "1.1.1",
            "--catalog-item",
            "M-00FA_H-1_P-1_CI-1",
        ])
        .expect("package catalogue selector parses");
        let Command::Add { product, catalog_item, .. } = parsed.command else {
            panic!("add command expected");
        };
        assert_eq!(product, PathBuf::from("products.knxprod"));
        assert_eq!(catalog_item.as_deref(), Some("M-00FA_H-1_P-1_CI-1"));

        assert!(
            Args::try_parse_from([
                "knx-loader",
                "add",
                "button",
                "products.knxprod",
                "--address",
                "1.1.1",
                "--catalog-product",
                "M-00FA_H-1_P-1",
            ])
            .is_err()
        );
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "import-product", "products.knxprod"])
                .expect("standalone package import parses")
                .command,
            Command::ImportProduct { .. }
        ));
    }

    #[test]
    fn cli_exposes_separate_address_load_and_combined_operations() {
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "address", "button", "--program-ia"])
                .expect("address command parses")
                .command,
            Command::Address { program_ia: true, .. }
        ));
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "load", "button"]).expect("application command parses").command,
            Command::Load { .. }
        ));
        assert!(matches!(
            Args::try_parse_from([
                "knx-loader",
                "program",
                "button",
                "--program-ia",
                "--programming-mode-timeout",
                "45"
            ])
            .expect("combined command parses")
            .command,
            Command::Program { program_ia: true, programming_mode_timeout: Some(45), .. }
        ));
        assert!(Args::try_parse_from(["knx-loader", "load", "button", "--program-ia"]).is_err());
        assert!(Args::try_parse_from(["knx-loader", "program", "button", "--programming-mode-timeout", "45"]).is_err());
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "load", "button", "--full"])
                .expect("full application command parses")
                .command,
            Command::Load { full: true, .. }
        ));
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "program", "button", "--full"])
                .expect("full combined command parses")
                .command,
            Command::Program { full: true, .. }
        ));

        assert_eq!(ProgrammingOperation::Address.requested_intent(false), CommissioningIntent::AssignAddress);
        assert_eq!(
            ProgrammingOperation::Load.requested_intent(false),
            CommissioningIntent::Download(DownloadMode::Automatic)
        );
        assert_eq!(
            ProgrammingOperation::Load.requested_intent(true),
            CommissioningIntent::Download(DownloadMode::Full)
        );
        assert_eq!(
            ProgrammingOperation::Program.requested_intent(false),
            CommissioningIntent::AssignAddressAndDownload(DownloadMode::Automatic)
        );
        assert_eq!(
            ProgrammingOperation::Program.requested_intent(true),
            CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full)
        );
    }

    #[test]
    fn add_authors_rf_and_ip_topology_without_family_defaults() {
        let rf = Args::try_parse_from([
            "knx-loader",
            "add",
            "rf-coupler",
            "product.knxprod",
            "--address",
            "1.1.0",
            "--medium",
            "rf",
            "--domain",
            "00:FA:12:34:56:78",
            "--rf-mode",
            "multi",
            "--routing",
            "filter",
        ])
        .expect("RF topology parses");
        let Command::Add { address, topology, .. } = rf.command else {
            panic!("add command expected");
        };
        let topology = topology.to_draft(address).expect("RF topology lowers");
        assert_eq!(topology.domain, Some(DomainAddress::Rf([0x00, 0xFA, 0x12, 0x34, 0x56, 0x78])));
        assert_eq!(topology.rf_mode, Some(RfDeviceMode::Multi));
        assert_eq!(topology.routing, Some(CouplerRoutingPolicy::Filter));

        let ip = Args::try_parse_from([
            "knx-loader",
            "add",
            "ip-router",
            "product.knxprod",
            "--address",
            "1.1.1",
            "--medium",
            "ip",
            "--domain",
            "224.0.23.12",
            "--project-installation-id",
            "42.3",
            "--multicast-latency-tolerance",
            "2000",
            "--sync-latency-fraction",
            "2",
            "--ip-assignment",
            "fixed",
            "--ip-address",
            "192.0.2.10",
            "--subnet-mask",
            "255.255.255.0",
            "--default-gateway",
            "192.0.2.1",
            "--multicast-ttl",
            "16",
            "--friendly-name",
            "Main IP router",
            "--additional-address",
            "1.1.2",
            "--ip-routing",
            "secure",
            "--ip-device-management",
            "secure",
            "--ip-tunnelling",
            "secure",
            "--ip-password-user",
            "1",
            "--ip-tunnelling-user",
            "2:1",
        ])
        .expect("KNX/IP topology parses");
        let Command::Add { address, topology, .. } = ip.command else {
            panic!("add command expected");
        };
        let topology = topology.to_draft(address).expect("KNX/IP topology lowers");
        assert_eq!(topology.domain, Some(DomainAddress::Ip([224, 0, 23, 12])));
        assert_eq!(topology.ip_line.expect("IP line values exist").project_installation_id.encode(), 0x02A3);
        assert!(validate_ip_configuration_ownership(&topology, &IpConfigurationMode::Tool).is_ok());
        assert!(validate_ip_configuration_ownership(&topology, &IpConfigurationMode::Custom).is_err());
        let ip = topology.ip.expect("IP device values exist");
        assert!(matches!(ip.assignment, IpAssignment::Fixed { address: [192, 0, 2, 10], .. }));
        assert_eq!(ip.security.expect("IP Secure policy exists").tunnelling_users[0].address_index, 1);
    }

    #[test]
    fn cli_exposes_project_wide_affected_programming() {
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "program", "--affected"])
                .expect("project-wide affected command parses")
                .command,
            Command::Program { device: None, affected: true, .. }
        ));
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "load", "--affected"])
                .expect("project-wide affected load parses")
                .command,
            Command::Load { device: None, affected: true, .. }
        ));
        assert!(Args::try_parse_from(["knx-loader", "program", "--all"]).is_err());
        assert!(Args::try_parse_from(["knx-loader", "load", "--all"]).is_err());
        let removed_single_device_alias = ["--force", "-single"].concat();
        assert!(
            Args::try_parse_from(["knx-loader", "program", "button", removed_single_device_alias.as_str()]).is_err()
        );
        assert!(Args::try_parse_from(["knx-loader", "load", "button", removed_single_device_alias.as_str()]).is_err());
        assert!(Args::try_parse_from(["knx-loader", "program", "button", "--affected"]).is_err());

        let (selected, selection) = programming_selection(None, true, false, ProgrammingOperation::Program)
            .expect("affected selection resolves");
        assert!(selected.is_empty());
        assert_eq!(selection, BatchSelection::AllStale);

        let selected_with_affected =
            programming_selection(Some("button".into()), true, false, ProgrammingOperation::Program);

        assert!(selected_with_affected.is_err());
    }

    #[test]
    fn cli_exposes_application_and_complete_unload() {
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "unload", "button", "--application"])
                .expect("application unload parses")
                .command,
            Command::Unload { device, application: true, all: false } if device == "button"
        ));
        assert!(matches!(
            Args::try_parse_from(["knx-loader", "unload", "button", "--all"])
                .expect("complete unload parses")
                .command,
            Command::Unload { device, application: false, all: true } if device == "button"
        ));
        assert!(Args::try_parse_from(["knx-loader", "unload", "button", "--all", "--application"]).is_err());
        assert!(Args::try_parse_from(["knx-loader", "unload", "button"]).is_err());

        assert_eq!(cli_unload_mode(true, false).expect("scope is explicit"), UnloadMode::Application);
        assert_eq!(cli_unload_mode(false, true).expect("scope is explicit"), UnloadMode::AllConfiguration);
    }

    #[test]
    fn status_names_group_section_changes() {
        let status = zweidraehte_project::DeviceProgrammingStatus {
            group_communication: false,
            ..zweidraehte_project::DeviceProgrammingStatus::ALL
        };
        assert_eq!(changed_programming_components(status), ["Grp"]);
    }

    #[test]
    fn device_certificate_supplies_and_reconciles_the_serial() {
        let decoded = parse_fdsk("AD5N5L-N654AA-CAQDAQ-CQMBYI-BEFAWD-ANBYHX").expect("certificate parses");
        assert_eq!(
            reconcile_certificate_serial(None, Some(&decoded)).expect("embedded serial is accepted"),
            Some([0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF])
        );
        let error = reconcile_certificate_serial(Some([0; 6]), Some(&decoded))
            .expect_err("a conflicting explicit serial is rejected");
        assert!(error.to_string().contains("disagrees with --serial"));
    }

    #[test]
    fn keyring_export_encrypts_a_new_file_without_replacing_existing_secrets() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project_path = directory.path().join("project.knx");
        fs::write(&project_path, "").expect("project writes");
        let mut store = ProjectStore::open(&project_path).expect("project opens");
        store = store.initialize().expect("project initializes");
        let output = directory.path().join("roundtrip.knxkeys");
        let args = Args::try_parse_from([
            "knx-loader",
            "--keyring-password",
            "secret",
            "export-keyring",
            "--out",
            output.to_str().expect("temporary path is UTF-8"),
        ])
        .expect("export command parses");
        let Command::ExportKeyring { out, name } = args.command else {
            panic!("export command expected");
        };
        run_export_keyring(&store, &args.security, &out, name.as_deref()).expect("project keyring exports");
        let exported = Keyring::load(&output, "secret").expect("project keyring imports again");
        assert_eq!(exported.group_key_count(), 0);
        let error = run_export_keyring(&store, &args.security, &out, name.as_deref())
            .expect_err("an existing secret file is not replaced");
        assert!(error.to_string().contains("create keyring"));
    }
}
