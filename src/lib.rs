use std::{collections::HashMap, fmt::Debug, ops};

pub trait AccessMask: Debug + Clone + ops::BitAnd<Self, Output = Self> {}

#[derive(Debug, Clone)]
pub enum Effect<A: AccessMask> {
    Allow(Option<A>),
    Deny,
    Next(Option<A>),
}

#[derive(Debug, Clone)]
pub enum Subject {
    User(String),
    Group(Vec<String>),
    Everyone,
}

#[derive(Debug, Clone)]
pub struct Entry<A: AccessMask> {
    pub subject: Subject,
    pub effect: Effect<A>,
}

#[derive(Debug, Clone)]
pub struct SecurityDescriptor<A: AccessMask> {
    pub acl: Vec<Entry<A>>,
}

#[derive(Debug, Clone)]
pub enum Item<A: AccessMask> {
    Object(SecurityDescriptor<A>),
    Prefix(Prefix<A>),
}

#[derive(Debug, Clone)]
pub struct Prefix<A: AccessMask> {
    pub self_security: Option<SecurityDescriptor<A>>,
    pub items: HashMap<String, Item<A>>,
}

impl<A: AccessMask> Prefix<A> {
    pub fn new() -> Prefix<A> {
        Prefix{
            self_security: None,
            items: HashMap::new(),
        }
    }

    pub fn new_with_access(access: A) -> Prefix<A> {
        let entry = Entry {
            subject: Subject::Everyone,
            effect: Effect::Next(Some(access))
        };

        let sec=SecurityDescriptor{
            acl: vec![entry]
        };
        Prefix {
            self_security: Some(sec),
            items: HashMap::new(),
        }
    }

    pub fn add_item(&mut self, name: &str, item: &Item<A>) {
        self.items.insert(name.to_string(), item.clone());
    }
}

#[derive(Debug, Clone)]
pub struct User {
    name: String,
    groups: Vec<String>,
}

impl Subject {
    fn covers(&self, user: &User) -> bool {
        match self {
            Subject::User(ref login) => &user.name == login,
            Subject::Group(ref groups) => groups.iter().all(|gr| user.groups.contains(gr)),
            Subject::Everyone => true,
        }
    }
}

pub enum CheckResult<A: AccessMask> {
    Allow(A),
    Deny,
    NoMatch,
    NotFound,
}

impl<A: AccessMask> SecurityDescriptor<A> {
    pub fn new() -> SecurityDescriptor<A> {
        SecurityDescriptor { acl: Vec::new() }
    }

    pub fn add_entry(&mut self, entry: Entry<A>) {
        self.acl.push(entry)
    }

    fn update_access(cur: &mut A, next: &Option<A>) {
        match next {
            None => (),
            Some(ref next) => {
                let ncur: A = cur.clone().bitand(next.clone());
                std::mem::replace(cur, ncur);
            }
        }
    }

    fn check(&self, user: &User, requested_access: A) -> CheckResult<A> {
        let mut provided_access = requested_access;
        for entry in &self.acl {
            if !entry.subject.covers(user) {
                continue;
            }
            match &entry.effect {
                Effect::Allow(next) => {
                    Self::update_access(&mut provided_access, next);
                    return CheckResult::Allow(provided_access);
                }
                Effect::Deny => {
                    return CheckResult::Deny;
                }
                Effect::Next(next) => {
                    Self::update_access(&mut provided_access, next);
                }
            }
        }
        CheckResult::NoMatch
    }
}

enum ItemRef<'a, A: AccessMask> {
    PrefixRef(&'a Prefix<A>),
    ObjectRef(&'a SecurityDescriptor<A>),
}

pub fn access<'dfl, A: AccessMask>(
    root: &'dfl Prefix<A>,
    user: &'dfl User,
    path: &'dfl[&'dfl str],
    requested_access: A,
) -> CheckResult<A> {
    let mut cur_item = ItemRef::PrefixRef(root);
    let mut cur_access = requested_access;
    for &segment in path {
        let cur_prefix = match cur_item {
            ItemRef::PrefixRef(pref) => pref,
            ItemRef::ObjectRef(_obj) => return CheckResult::NotFound,
        };
        if let Some(sec) = &cur_prefix.self_security {
            let check_res = sec.check(user, cur_access.clone());
            match check_res {
                CheckResult::Allow(acc) => {
                    cur_access = cur_access.bitand(acc);
                }
                CheckResult::Deny => {
                    return CheckResult::Deny;
                }
                CheckResult::NotFound => unreachable!(),
                CheckResult::NoMatch => return CheckResult::NoMatch,
            }
        }
        match cur_prefix.items.get(segment) {
            None => {
                return CheckResult::NotFound;
            }
            Some(item) => {
                cur_item = match item {
                    Item::Prefix(ref pref) => ItemRef::PrefixRef(pref),
                    Item::Object(ref obj) => ItemRef::ObjectRef(obj),
                };
            }
        }
    }
    let obj_sec = match cur_item {
        ItemRef::PrefixRef(_p) => return CheckResult::NotFound,
        ItemRef::ObjectRef( obj) => obj.clone()
    };
    obj_sec.check(user, cur_access)
}

/// Useful when you don't want any access right tracking to be done
#[derive(Debug, Clone)]
pub struct AccessNoop;

impl ops::BitAnd for AccessNoop {
    type Output = Self;

    fn bitand(self, _other: Self) -> Self {
        Self
    }
}

impl AccessMask for AccessNoop {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simple() {
        let mut root = Prefix::new_with_access(AccessNoop);
        root.self_security.as_mut().unwrap().add_entry(Entry{
           subject: Subject::Everyone,
            effect:Effect::Allow(None),
        });
        let mut object = SecurityDescriptor::new();
        {
            let entry = Entry {
                subject: Subject::Group(vec!["admin".into()]),
                effect: Effect::Allow(None)
            };

            object.add_entry(entry);
        }
        {
            let entry = Entry {
                subject: Subject::Everyone,
                effect: Effect::Deny
            };

            object.add_entry(entry);
        }
            root.add_item("top-secret", &Item::Object(object));

        let joe_admin = User {
            name: "joe".to_string(),
            groups: vec!["admin".to_string(), "jojo-fan".to_string()]
        };

        let bob_hacker =  User {
            name: "bob".to_string(),
            groups: vec!["jojo-fan".to_string()]
        };

        let path = &["top-secret"];

        let joe_access = access(&root, &joe_admin, path, AccessNoop);
        //assert_eq!(joe_access, Some(AccessNoop));
        match joe_access {
            CheckResult::Allow(AccessNoop) => (),
            _ => panic!("test failed"),
        }

        let bob_access = access(&root, &bob_hacker, path, AccessNoop);
        match bob_access {
            CheckResult::Deny => (),
            _ => panic!("test failed"),
        }
        //assert_eq!(bob_access, None);
    }

    impl AccessMask for u64 {}

    #[test]
    fn access_crop() {
        let mut root = Prefix::new_with_access(5);
        root.self_security.as_mut().unwrap().add_entry(Entry{
            subject: Subject::Everyone,
            effect:Effect::Allow(None),
        });
        let mut object = SecurityDescriptor::new();
        {
            let entry = Entry {
                subject: Subject::Group(vec!["admin".into()]),
                effect: Effect::Allow(Some(6))
            };

            object.add_entry(entry);
        }
        {
            let entry = Entry {
                subject: Subject::Everyone,
                effect: Effect::Deny
            };

            object.add_entry(entry);
        }
        root.add_item("top-secret", &Item::Object(object));

        let joe_admin = User {
            name: "joe".to_string(),
            groups: vec!["admin".to_string(), "jojo-fan".to_string()]
        };

        let path = &["top-secret"];

        let joe_access = access(&root, &joe_admin, path, 255);
        //assert_eq!(joe_access, Some(AccessNoop));
        match joe_access {
            CheckResult::Allow(4) => (),
            _ => panic!("test failed"),
        }
    }
}
