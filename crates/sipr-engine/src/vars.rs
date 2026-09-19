//! Layered variable storage: a call's own values, its user's (one table per
//! user id, kept for the whole run) and the run-wide globals — SIPp's
//! `VariableTable` chain (`call` → `userVarMap[userId]` → `globalVariables`,
//! `call.cpp` ~l.1100). The scope of every variable id is fixed when the
//! engine starts, so an access is an index into one layer, never a search
//! (docs/ARCHITECTURE.md §4). The engine is single-threaded: the shared
//! layers are `Rc<RefCell<…>>`, and a borrow never outlives one expression.

use std::cell::{Ref, RefCell};
use std::ops::Deref;
use std::rc::Rc;

use sipr_scenario::model::{VarId, VarScope, VarTable};

use crate::actions::Value;

static UNSET: Value = Value::Unset;

/// Where one of a scenario's variable ids lives.
#[derive(Debug, Clone, Copy)]
enum Slot {
    Call(usize),
    User(usize),
    Global(usize),
}

/// A scenario's variable ids mapped to a layer and an index in it.
#[derive(Debug)]
pub struct VarLayout {
    slots: Vec<Slot>,
    call_len: usize,
}

/// A table several calls read and write: one per user id, one global.
#[derive(Debug, Clone, Default)]
pub struct SharedTable(Rc<RefCell<Vec<Value>>>);

impl SharedTable {
    fn with_len(len: usize) -> Self {
        Self(Rc::new(RefCell::new(vec![Value::Unset; len])))
    }

    fn get(&self, index: usize) -> VarRef<'_> {
        match Ref::filter_map(self.0.borrow(), |table| table.get(index)) {
            Ok(value) => VarRef::Shared(value),
            Err(_) => VarRef::Direct(&UNSET),
        }
    }

    /// Write one slot (`-set` seeds the global table this way).
    pub(crate) fn set(&self, index: usize, value: Value) {
        if let Some(slot) = self.0.borrow_mut().get_mut(index) {
            *slot = value;
        }
    }
}

/// A borrowed variable value from whichever layer holds it.
pub enum VarRef<'a> {
    /// From the call's own layer.
    Direct(&'a Value),
    /// From a shared (user or global) layer.
    Shared(Ref<'a, Value>),
}

impl Deref for VarRef<'_> {
    type Target = Value;

    fn deref(&self) -> &Value {
        match self {
            Self::Direct(value) => value,
            Self::Shared(value) => value,
        }
    }
}

impl std::fmt::Debug for VarRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Value::fmt(self, f)
    }
}

/// The run's user and global name tables — SIPp's `userVariables` and
/// `globalVariables`, shared by every scenario so that the main scenario's
/// `<Global variables="g"/>` and the secondary's name the same slot.
#[derive(Debug, Default)]
pub struct VarSpace {
    user_names: Vec<String>,
    global_names: Vec<String>,
    /// Names one scenario declared `<User>` and another `<Global>`.
    conflicts: Vec<String>,
}

impl VarSpace {
    /// Union the user- and global-scoped names of every scenario's table.
    #[must_use]
    pub fn new(tables: &[&VarTable]) -> Self {
        let mut space = Self::default();
        for vars in tables {
            for (_, name) in vars.in_scope(VarScope::User) {
                if space.global_names.iter().any(|n| n == name) {
                    space.note_conflict(name);
                } else if !space.user_names.iter().any(|n| n == name) {
                    space.user_names.push(name.to_owned());
                }
            }
            for (_, name) in vars.in_scope(VarScope::Global) {
                if space.user_names.iter().any(|n| n == name) {
                    space.note_conflict(name);
                } else if !space.global_names.iter().any(|n| n == name) {
                    space.global_names.push(name.to_owned());
                }
            }
        }
        space
    }

    fn note_conflict(&mut self, name: &str) {
        if !self.conflicts.iter().any(|n| n == name) {
            self.conflicts.push(name.to_owned());
        }
    }

    /// Names whose scope the scenarios disagree on (a start-up error).
    #[must_use]
    pub fn conflicts(&self) -> &[String] {
        &self.conflicts
    }

    /// The user-scoped names, in slot order.
    #[must_use]
    pub fn user_names(&self) -> &[String] {
        &self.user_names
    }

    /// The global names, in slot order.
    #[must_use]
    pub fn global_names(&self) -> &[String] {
        &self.global_names
    }

    /// The global slot of `name` (`-set`).
    #[must_use]
    pub fn global_slot(&self, name: &str) -> Option<usize> {
        self.global_names.iter().position(|n| n == name)
    }

    /// The layout of one scenario's variable table in this space.
    #[must_use]
    pub fn layout(&self, vars: &VarTable) -> Rc<VarLayout> {
        let mut call_len = 0;
        let slots = (0..vars.len())
            .map(|id| {
                let name = vars.name(id);
                let shared = |names: &[String]| names.iter().position(|n| n == name);
                match vars.scope(id) {
                    VarScope::User => shared(&self.user_names).map(Slot::User),
                    VarScope::Global => shared(&self.global_names).map(Slot::Global),
                    VarScope::Call => None,
                }
                .unwrap_or_else(|| {
                    call_len += 1;
                    Slot::Call(call_len - 1)
                })
            })
            .collect();
        Rc::new(VarLayout { slots, call_len })
    }

    /// A fresh user table (all unset).
    #[must_use]
    pub fn user_table(&self) -> SharedTable {
        SharedTable::with_len(self.user_names.len())
    }

    /// A fresh global table (all unset).
    #[must_use]
    pub fn global_table(&self) -> SharedTable {
        SharedTable::with_len(self.global_names.len())
    }
}

/// One call's view of the variables: its own layer plus the shared user and
/// global layers it was given at creation.
#[derive(Debug, Clone)]
pub struct VarStore {
    call: Vec<Value>,
    user: SharedTable,
    global: SharedTable,
    layout: Rc<VarLayout>,
}

impl VarStore {
    /// A store over the given layers.
    #[must_use]
    pub fn new(layout: Rc<VarLayout>, user: SharedTable, global: SharedTable) -> Self {
        Self {
            call: vec![Value::Unset; layout.call_len],
            user,
            global,
            layout,
        }
    }

    /// A store for a scenario on its own, with private user and global
    /// layers — what a call with no user id gets for its user layer, and
    /// what tests use.
    #[must_use]
    pub fn standalone(vars: &VarTable) -> Self {
        let space = VarSpace::new(&[vars]);
        Self::new(space.layout(vars), space.user_table(), space.global_table())
    }

    /// Read a variable (Unset if out of range).
    #[must_use]
    pub fn get(&self, id: VarId) -> VarRef<'_> {
        match self.layout.slots.get(id).copied() {
            Some(Slot::Call(i)) => VarRef::Direct(self.call.get(i).unwrap_or(&UNSET)),
            Some(Slot::User(i)) => self.user.get(i),
            Some(Slot::Global(i)) => self.global.get(i),
            None => VarRef::Direct(&UNSET),
        }
    }

    /// Write a variable (ignored if out of range — the compiler guarantees
    /// the range).
    pub fn set(&mut self, id: VarId, value: Value) {
        match self.layout.slots.get(id).copied() {
            Some(Slot::Call(i)) => {
                if let Some(slot) = self.call.get_mut(i) {
                    *slot = value;
                }
            }
            Some(Slot::User(i)) => self.user.set(i, value),
            Some(Slot::Global(i)) => self.global.set(i, value),
            None => {}
        }
    }

    /// Is this variable set? (backs `test`/`condexec`).
    #[must_use]
    pub fn is_set(&self, id: VarId) -> bool {
        self.get(id).is_set()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table with `call` call-scoped, `u` user-scoped and `g` global.
    fn scoped_table() -> VarTable {
        let mut vars = VarTable::default();
        vars.intern("call");
        let u = vars.intern("u");
        let g = vars.intern("g");
        vars.set_scope(u, VarScope::User);
        vars.set_scope(g, VarScope::Global);
        vars
    }

    fn num(store: &VarStore, id: VarId) -> f64 {
        store.get(id).as_num()
    }

    #[test]
    fn a_user_variable_survives_into_the_same_users_next_call() {
        let vars = scoped_table();
        let space = VarSpace::new(&[&vars]);
        let layout = space.layout(&vars);
        let global = space.global_table();
        let user_7 = space.user_table();

        let mut first = VarStore::new(layout.clone(), user_7.clone(), global.clone());
        first.set(0, Value::Num(1.0));
        first.set(1, Value::Num(10.0));
        first.set(2, Value::Num(100.0));
        drop(first);

        // The user's next call: user and global values persist, the call
        // variable starts unset.
        let next = VarStore::new(layout, user_7, global);
        assert!(!next.is_set(0), "call variables reset per call");
        assert_eq!(num(&next, 1), 10.0, "user variable persists per user id");
        assert_eq!(num(&next, 2), 100.0, "global persists");
    }

    #[test]
    fn a_global_is_visible_to_every_call_and_a_user_variable_is_not() {
        let vars = scoped_table();
        let space = VarSpace::new(&[&vars]);
        let layout = space.layout(&vars);
        let global = space.global_table();
        let mut alice = VarStore::new(layout.clone(), space.user_table(), global.clone());
        let bob = VarStore::new(layout, space.user_table(), global);

        alice.set(1, Value::Str("alice".into()));
        alice.set(2, Value::Str("shared".into()));
        assert_eq!(bob.get(2).as_str(), "shared");
        assert!(!bob.is_set(1), "another user's variable is private");
        assert_eq!(alice.get(1).as_str(), "alice");
    }

    #[test]
    fn a_call_without_a_user_id_does_not_leak_user_variables() {
        // SIPp gives such a call (UAS, ooc, rx) a fresh table parented on
        // `userVariables`: "user" variables are then per call.
        let vars = scoped_table();
        let space = VarSpace::new(&[&vars]);
        let layout = space.layout(&vars);
        let global = space.global_table();
        let mut first = VarStore::new(layout.clone(), space.user_table(), global.clone());
        first.set(1, Value::Num(5.0));
        let next = VarStore::new(layout, space.user_table(), global);
        assert!(!next.is_set(1));
    }

    #[test]
    fn the_space_unions_names_across_scenarios_by_scope() {
        let main = scoped_table();
        let mut other = VarTable::default();
        let g2 = other.intern("g2");
        other.set_scope(g2, VarScope::Global);
        let g = other.intern("g");
        other.set_scope(g, VarScope::Global);
        let space = VarSpace::new(&[&main, &other]);
        assert_eq!(space.global_names(), ["g", "g2"]);
        assert_eq!(space.user_names(), ["u"]);
        assert!(space.conflicts().is_empty());

        // Both scenarios' `g` land on the same slot.
        let global = space.global_table();
        let mut a = VarStore::new(space.layout(&main), space.user_table(), global.clone());
        let b = VarStore::new(space.layout(&other), space.user_table(), global);
        a.set(2, Value::Num(3.0));
        assert_eq!(num(&b, g), 3.0);
        assert_eq!(space.global_slot("g2"), Some(1));
        assert_eq!(space.global_slot("nope"), None);
    }

    #[test]
    fn a_name_scoped_differently_by_two_scenarios_is_a_conflict() {
        let main = scoped_table();
        let mut other = VarTable::default();
        let u = other.intern("u");
        other.set_scope(u, VarScope::Global);
        let space = VarSpace::new(&[&main, &other]);
        assert_eq!(space.conflicts(), ["u"]);
    }

    #[test]
    fn out_of_range_ids_read_unset_and_ignore_writes() {
        let vars = scoped_table();
        let mut store = VarStore::standalone(&vars);
        assert!(!store.is_set(42));
        store.set(42, Value::Num(1.0));
        assert!(!store.is_set(42));
        // Standalone stores share nothing.
        let mut a = VarStore::standalone(&vars);
        a.set(2, Value::Num(1.0));
        assert!(!store.is_set(2));
    }
}
