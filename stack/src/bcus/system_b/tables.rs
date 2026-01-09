//! Tables container for System B devices.
//!
//! This module provides [`SystemBTables`], a container for all the tables
//! required by a System B device, with support for persistence.

use core::cell::RefCell;

use const_default::ConstDefault;

use crate::{
    memory::{HasAddressTable, HasAssociationTable, HasCommunicationObjectTable},
    objects::tables::{
        LoadableTable, RunnableTable, Table, TableMemory,
        addr7::AddrTab7Impl,
        app::Application,
        asso6::AssoTab6Impl,
        co7::CoTab7Impl,
    },
};

use super::{PersistedApplication, PersistedState, PersistedTable};

/// Tables container for System B devices.
///
/// Contains all the tables required by a System B device:
/// - Address Table (ADT): Maps TSAP → Group Address
/// - Association Table (AST): Maps TSAP → ASAP
/// - Group Object Table (COT): Communication object type + flags
/// - Application Program (APP): Application data + Load/Run state machines
///
/// # Persistence
///
/// Tables can be loaded from and saved to [`PersistedState`].
/// Use [`from_persisted`](Self::from_persisted) to restore tables from storage,
/// and [`to_persisted`](Self::to_persisted) to prepare tables for saving.
///
/// # Generic Parameters
///
/// The size parameters are the actual byte sizes (not entry counts):
/// - `ADT_SIZE`: Address table size in bytes (2 + MAX_ADDR * 2)
/// - `AST_SIZE`: Association table size in bytes (2 + MAX_ASSO * 4)
/// - `COT_SIZE`: Group object table size in bytes (2 + MAX_CO * 2)
/// - `APP_SIZE`: Maximum application data size in bytes
/// - `P`: Application parameters type (stored in application table)
///
/// Use [`SystemBDeviceExt::ADT_SIZE`](super::SystemBDeviceExt) etc. to compute
/// sizes from entry counts.
pub struct SystemBTables<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    const APP_SIZE: usize,
    P: ConstDefault = (),
> {
    /// Address table (TSAP → Group Address mapping).
    pub adt: RefCell<Table<AddrTab7Impl<ADT_SIZE>>>,

    /// Association table (TSAP → ASAP mapping).
    pub ast: RefCell<Table<AssoTab6Impl<AST_SIZE>>>,

    /// Group object table (CO type + flags).
    pub cot: RefCell<Table<CoTab7Impl<COT_SIZE>>>,

    /// Application program (data + Load/Run state machines).
    pub app: RefCell<Application<P>>,
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize, P: ConstDefault>
    SystemBTables<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE, P>
{
    /// Create new tables in unloaded state.
    pub fn new() -> Self {
        Self {
            adt: RefCell::new(Table::new()),
            ast: RefCell::new(Table::new()),
            cot: RefCell::new(Table::new()),
            app: RefCell::new(Application::new()),
        }
    }

    /// Create tables from persisted state.
    ///
    /// Restores table data and load states from storage.
    /// The application's run state is always set to `Halted` - it must
    /// be explicitly restarted after boot.
    pub fn from_persisted(
        persisted: &PersistedState<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE>,
    ) -> Self {
        Self {
            adt: RefCell::new(Self::table_from_persisted(&persisted.address_table)),
            ast: RefCell::new(Self::table_from_persisted(&persisted.association_table)),
            cot: RefCell::new(Self::table_from_persisted(&persisted.group_object_table)),
            app: RefCell::new(Self::app_from_persisted(&persisted.application)),
        }
    }

    /// Export tables to persisted state components.
    ///
    /// Returns the table data ready for inclusion in a [`PersistedState`].
    pub fn to_persisted(
        &self,
    ) -> (
        PersistedTable<ADT_SIZE>,
        PersistedTable<AST_SIZE>,
        PersistedTable<COT_SIZE>,
        PersistedApplication<APP_SIZE>,
    ) {
        (
            self.table_to_persisted(&self.adt.borrow()),
            self.table_to_persisted(&self.ast.borrow()),
            self.table_to_persisted(&self.cot.borrow()),
            self.app_to_persisted(&self.app.borrow()),
        )
    }

    /// Helper to create a table from persisted data.
    fn table_from_persisted<T, const SIZE: usize>(
        persisted: &PersistedTable<SIZE>,
    ) -> Table<T>
    where
        T: TableMemory,
    {
        let mut table = Table::<T>::new();
        table.set_load_state(persisted.load_state);

        // Copy data
        let data_ref = table.data_ref_mut();
        let len = persisted.data.len().min(data_ref.len());
        data_ref[..len].copy_from_slice(&persisted.data[..len]);

        // Copy MCB
        let mcb_len = persisted.mcb.len().min(8);
        table.mcb_bytes_mut()[..mcb_len].copy_from_slice(&persisted.mcb[..mcb_len]);

        table
    }

    /// Helper to export a table to persisted form.
    fn table_to_persisted<T, const SIZE: usize>(
        &self,
        table: &Table<T>,
    ) -> PersistedTable<SIZE>
    where
        T: TableMemory,
    {
        let mut data = [0u8; SIZE];
        let table_data = table.data_ref();
        let len = table_data.len().min(SIZE);
        data[..len].copy_from_slice(&table_data[..len]);

        let mut mcb = [0u8; 8];
        mcb.copy_from_slice(table.mcb_bytes());

        PersistedTable {
            load_state: table.load_state(),
            data,
            mcb,
        }
    }

    /// Helper to create an application from persisted data.
    fn app_from_persisted(persisted: &PersistedApplication<APP_SIZE>) -> Application<P> {
        let mut app = Application::<P>::new();

        // Restore load state
        app.inner_mut().set_load_state(persisted.load_state);

        // Copy data
        let data_ref = app.inner_mut().data_ref_mut();
        let len = persisted.data.len().min(data_ref.len());
        data_ref[..len].copy_from_slice(&persisted.data[..len]);

        // Copy MCB
        let mcb_len = persisted.mcb.len().min(8);
        app.inner_mut().mcb_bytes_mut()[..mcb_len].copy_from_slice(&persisted.mcb[..mcb_len]);

        // Run state is always Halted on boot - must be explicitly restarted
        // (already default from Application::new())

        app
    }

    /// Helper to export an application to persisted form.
    fn app_to_persisted(&self, app: &Application<P>) -> PersistedApplication<APP_SIZE> {
        let mut data = [0u8; APP_SIZE];
        let app_data = app.inner().data_ref();
        let len = app_data.len().min(APP_SIZE);
        data[..len].copy_from_slice(&app_data[..len]);

        let mut mcb = [0u8; 8];
        mcb.copy_from_slice(app.inner().mcb_bytes());

        PersistedApplication {
            load_state: app.inner().load_state(),
            data,
            mcb,
        }
    }

    /// Check if all tables are loaded.
    pub fn all_loaded(&self) -> bool {
        self.adt.borrow().is_loaded()
            && self.ast.borrow().is_loaded()
            && self.cot.borrow().is_loaded()
            && self.app.borrow().is_loaded()
    }

    /// Check if the application is running.
    pub fn is_running(&self) -> bool {
        self.app.borrow().is_running()
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize, P: ConstDefault>
    Default for SystemBTables<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE, P>
{
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Trait Implementations for Stack Integration
// ============================================================================

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize, P: ConstDefault>
    HasAddressTable for SystemBTables<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE, P>
{
    type ADT = Table<AddrTab7Impl<ADT_SIZE>>;

    fn adt(&self) -> &RefCell<Self::ADT> {
        &self.adt
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize, P: ConstDefault>
    HasAssociationTable for SystemBTables<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE, P>
{
    type AST = Table<AssoTab6Impl<AST_SIZE>>;

    fn ast(&self) -> &RefCell<Self::AST> {
        &self.ast
    }
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize, P: ConstDefault>
    HasCommunicationObjectTable for SystemBTables<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE, P>
{
    type COT = Table<CoTab7Impl<COT_SIZE>>;

    fn cot(&self) -> &RefCell<Self::COT> {
        &self.cot
    }
}

/// Trait for types that contain an Application Program.
///
/// This is used by interface objects and the memory map to access
/// the application's load and run state machines.
pub trait HasApplication {
    /// The concrete application type.
    type APP: LoadableTable + RunnableTable;

    /// Get a reference to the application.
    fn app(&self) -> &RefCell<Self::APP>;
}

impl<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, const APP_SIZE: usize, P: ConstDefault>
    HasApplication for SystemBTables<ADT_SIZE, AST_SIZE, COT_SIZE, APP_SIZE, P>
{
    type APP = Application<P>;

    fn app(&self) -> &RefCell<Self::APP> {
        &self.app
    }
}
