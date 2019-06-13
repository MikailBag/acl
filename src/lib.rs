use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum Effect {
    Allow(Option<u64>),
    Deny,
    Next(Option<u64>),
}

#[derive(Debug, Clone)]
pub enum RuleSubject {
    User(String),
    Group(String),
    Everyone,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub subject: RuleSubject,
    pub effect: Effect,
}

#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    pub acl: Vec<Entry>,
}

#[derive(Debug, Clone)]
pub struct Object {
    pub security: SecurityDescriptor,
}

#[derive(Debug, Clone)]
pub enum Item {
    Object(Object),
    Prefix(Prefix),
}

/// Represents security subject - e.g. user, process, etc
#[derive(Debug, Clone, Copy)]
pub struct AccessToken<'a> {
    name: &'a str,
    groups: &'a [String],
}

#[derive(Debug, Clone)]
pub struct Prefix {
    self_security: SecurityDescriptor,
    items: HashMap<String, Item>,
}

impl Default for Prefix {
    fn default() -> Prefix {
        Prefix::new()
    }
}

impl Prefix {
    pub fn new() -> Prefix {
        Prefix {
            self_security: SecurityDescriptor::allow_all(),
            items: HashMap::new(),
        }
    }

    pub fn with_security(sec: SecurityDescriptor) -> Prefix {
        Prefix {
            self_security: sec,
            items: HashMap::new(),
        }
    }

    pub fn set_self_security(&mut self, sec: SecurityDescriptor) {
        std::mem::replace(&mut self.self_security, sec);
    }

    pub fn add_item(&mut self, name: &str, item: Item) {
        self.items.insert(name.to_string(), item.clone());
    }

    fn self_security(&self) -> &SecurityDescriptor {
        &self.self_security
    }

    fn get_item(&self, item_name: &str) -> Option<&Item> {
        self.items.get(item_name)
    }
}

impl RuleSubject {
    fn covers(&self, token: AccessToken) -> bool {
        match self {
            RuleSubject::User(ref login) => token.name == login,
            RuleSubject::Group(ref group) => token.groups.contains(&group),
            RuleSubject::Everyone => true,
        }
    }
}

/// Security descriptor lookup result
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CheckResult {
    /// Access to object is allowed. Associated u64 means, what rights are additionally granted
    Allow(u64),
    /// Access is denied
    Deny,
    /// No rule in ACL (neither allow nor deny) refers to subject
    NoMatch,
    /// Object not found, or path refers to prefix
    NotFound,
}

impl Default for SecurityDescriptor {
    fn default() -> SecurityDescriptor {
        SecurityDescriptor::allow_all()
    }
}

impl SecurityDescriptor {
    pub fn with_capped_access(max_access: u64) -> SecurityDescriptor {
        let acl = vec![Entry {
            subject: RuleSubject::Everyone,
            effect: Effect::Allow(Some(max_access)),
        }];
        SecurityDescriptor { acl }
    }

    pub fn deny_all() -> SecurityDescriptor {
        let acl = vec![Entry {
            subject: RuleSubject::Everyone,
            effect: Effect::Deny,
        }];
        SecurityDescriptor { acl }
    }

    pub fn allow_all() -> SecurityDescriptor {
        let acl = vec![Entry {
            subject: RuleSubject::Everyone,
            effect: Effect::Allow(None),
        }];

        SecurityDescriptor { acl }
    }

    pub fn empty() -> SecurityDescriptor {
        SecurityDescriptor { acl: Vec::new() }
    }

    pub fn add_entry(&mut self, entry: Entry) {
        self.acl.push(entry)
    }

    fn update_access(cur: &mut u64, next: Option<u64>) {
        use std::u64;
        let next = next.unwrap_or(u64::max_value());
        *cur &= next;
    }

    fn check(&self, token: AccessToken, requested_access: u64) -> CheckResult {
        let mut provided_access = requested_access;
        for entry in &self.acl {
            if !entry.subject.covers(token) {
                continue;
            }
            match &entry.effect {
                Effect::Allow(next) => {
                    Self::update_access(&mut provided_access, *next);
                    return CheckResult::Allow(provided_access);
                }
                Effect::Deny => {
                    return CheckResult::Deny;
                }
                Effect::Next(next) => {
                    Self::update_access(&mut provided_access, *next);
                }
            }
        }
        CheckResult::NoMatch
    }
}

#[derive(Copy, Clone)]
enum ItemRef<'a> {
    Prefix(&'a Prefix),
    Object(&'a Object),
}

impl<'a> ItemRef<'a> {
    fn as_object(self) -> Option<&'a Object> {
        match self {
            ItemRef::Prefix(_) => None,
            ItemRef::Object(obj) => Some(obj),
        }
    }
}

impl<'a> From<&'a Item> for ItemRef<'a> {
    fn from(it: &'a Item) -> ItemRef<'a> {
        match it {
            Item::Prefix(p) => ItemRef::Prefix(p),
            Item::Object(p) => ItemRef::Object(p),
        }
    }
}

/// If such an object exists in some prefix, and user has access to this object,
/// then this user has full access to prefix content
/// Access flags are ignored
pub const SPECIAL_SEGMENT_SUDO: &str = "$ACL.Sudo";

pub fn access<'a>(
    root: &Prefix,
    token: AccessToken,
    path: &'a [&'a str],
    requested_access: u64,
) -> CheckResult {
    let mut cur_item = ItemRef::Prefix(root);
    let mut cur_access = requested_access;
    for &segment in path {
        let cur_prefix = match cur_item {
            ItemRef::Prefix(pref) => pref,
            ItemRef::Object(_obj) => return CheckResult::NotFound,
        };
        {
            let check_res = cur_prefix.self_security().check(token, cur_access);
            match check_res {
                CheckResult::Allow(acc) => {
                    cur_access &= acc;
                }
                CheckResult::Deny => {
                    return CheckResult::Deny;
                }
                CheckResult::NotFound => unreachable!(),
                CheckResult::NoMatch => return CheckResult::NoMatch,
            }
        }
        // }
        match cur_prefix.get_item(SPECIAL_SEGMENT_SUDO) {
            None => {}
            Some(item) => {
                let item: ItemRef = item.into();
                let obj = item.as_object().unwrap();

                let check_res = obj.security.check(token, 0);
                if let CheckResult::Allow(_) = check_res {
                    // no more lookup
                    // sudo granted
                    return CheckResult::Allow(cur_access);
                }
            }
        };
        match cur_prefix.get_item(segment) {
            None => {
                return CheckResult::NotFound;
            }
            Some(item) => {
                cur_item = match item {
                    Item::Prefix(pref) => ItemRef::Prefix(pref),
                    Item::Object(obj) => ItemRef::Object(obj),
                };
            }
        }
    }
    let obj = match cur_item {
        ItemRef::Prefix(_p) => return CheckResult::NotFound,
        ItemRef::Object(obj) => obj,
    };
    obj.security.check(token, cur_access)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! s {
        ($x: tt) => {
            $x.to_string()
        };
    }
    #[test]
    fn simple() {
        let mut root = Prefix::new();
        let mut object = SecurityDescriptor::empty();
        {
            let entry = Entry {
                subject: RuleSubject::Group(s!("admin")),
                effect: Effect::Allow(None),
            };

            object.add_entry(entry);
        }
        {
            let entry = Entry {
                subject: RuleSubject::Everyone,
                effect: Effect::Deny,
            };

            object.add_entry(entry);
        }
        let object = Object { security: object };
        root.add_item("top-secret", Item::Object(object));

        let joe_admin = AccessToken {
            name: "joe",
            groups: &[s!("admin"), s!("jojo-fan")],
        };

        let bob_hacker = AccessToken {
            name: "bob",
            groups: &[s!("jojo-fan")],
        };

        let path = &["top-secret"];

        let joe_access = access(&root, joe_admin, path, 0);
        assert_eq!(joe_access, CheckResult::Allow(0));
        let bob_access = access(&root, bob_hacker, path, 0);
        assert_eq!(bob_access, CheckResult::Deny);
    }

    #[test]
    fn access_crop() {
        let root_security = SecurityDescriptor::with_capped_access(5);
        let mut root = Prefix::with_security(root_security);
        root.self_security.add_entry(Entry {
            subject: RuleSubject::Everyone,
            effect: Effect::Allow(None),
        });
        let mut object = SecurityDescriptor::empty();
        {
            let entry = Entry {
                subject: RuleSubject::Group("admin".to_string()),
                effect: Effect::Allow(Some(6)),
            };

            object.add_entry(entry);
        }
        {
            let entry = Entry {
                subject: RuleSubject::Everyone,
                effect: Effect::Deny,
            };

            object.add_entry(entry);
        }
        let object = Object { security: object };
        root.add_item("top-secret", Item::Object(object));

        let joe_admin = AccessToken {
            name: "joe",
            groups: &[s!("admin"), s!("jojo-fan")],
        };

        let path = &["top-secret"];

        let joe_access = access(&root, joe_admin, path, 255);
        assert_eq!(joe_access, CheckResult::Allow(4));
    }

    #[test]
    fn sudo_mode() {
        // root: no filter
        // root/$ACL.Sudo: allow for jon_snow
        // root/GotFinal: deny for all
        let mut root = Prefix::new();

        let sudo_object_security = SecurityDescriptor {
            acl: vec![Entry {
                subject: RuleSubject::User("jon_snow".to_string()),
                effect: Effect::Allow(Some(0)),
            }],
        };
        root.add_item(
            SPECIAL_SEGMENT_SUDO,
            Item::Object(Object {
                security: sudo_object_security,
            }),
        );

        let got_final_security = SecurityDescriptor::deny_all();

        root.add_item(
            "GotFinal",
            Item::Object(Object {
                security: got_final_security,
            }),
        );

        let path = &["GotFinal"];

        let jon_snow = AccessToken {
            name: "jon_snow",
            groups: &[],
        };

        let cersei = AccessToken {
            name: "cersei",
            groups: &[],
        };

        let jon_access = access(&root, jon_snow, path, 179);
        assert_eq!(jon_access, CheckResult::Allow(179));

        let cersei_access = access(&root, cersei, path, 179);
        assert_eq!(cersei_access, CheckResult::Deny);
    }
}
