use sentrycheck_core::Result;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct Args {
    pub positionals: Vec<String>,
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}
impl Args {
    pub fn parse(arguments: Vec<String>) -> Result<Self> {
        let mut result = Self {
            positionals: vec![],
            values: BTreeMap::new(),
            flags: BTreeSet::new(),
        };
        let mut iter = arguments.into_iter();
        let switches = ["static-only", "native-only", "no-cache", "force"];
        let mut positional = false;
        while let Some(arg) = iter.next() {
            if arg == "--" {
                positional = true;
                continue;
            }
            if !positional && arg.starts_with("--") {
                let key = &arg[2..];
                if switches.contains(&key) {
                    if !result.flags.insert(key.into()) {
                        return Err(format!("duplicate option --{key}"));
                    }
                } else {
                    let (key, value) = if let Some((key, value)) = key.split_once('=') {
                        (key.to_string(), value.to_string())
                    } else {
                        let value = iter
                            .next()
                            .ok_or_else(|| format!("--{key} requires a value"))?;
                        if value.starts_with("--") {
                            return Err(format!("--{key} requires a value"));
                        }
                        (key.to_string(), value)
                    };
                    if value.is_empty() || result.values.insert(key.clone(), value).is_some() {
                        return Err(format!("duplicate or empty option --{key}"));
                    }
                }
            } else if !positional && arg.starts_with('-') {
                return Err(format!("unknown option {arg}"));
            } else {
                result.positionals.push(arg);
            }
        }
        Ok(result)
    }
    pub fn value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    pub fn flag(&self, key: &str) -> bool {
        self.flags.contains(key)
    }
    pub fn only(&self, values: &[&str], flags: &[&str]) -> Result<()> {
        for key in self.values.keys() {
            if !values.contains(&key.as_str()) {
                return Err(format!("unknown option --{key}"));
            }
        }
        for key in &self.flags {
            if !flags.contains(&key.as_str()) {
                return Err(format!("unknown flag --{key}"));
            }
        }
        Ok(())
    }
    pub fn single_positional(&self, description: &str) -> Result<&str> {
        if self.positionals.len() != 1 {
            return Err(format!("expected one {description}"));
        }
        Ok(&self.positionals[0])
    }
    pub fn format(&self) -> Result<&str> {
        match self.value("format").unwrap_or("human") {
            "human" => Ok("human"),
            "json" => Ok("json"),
            _ => Err("--format must be human or json".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn options_fail_closed() {
        assert!(Args::parse(vec!["--version".into(), "--format".into()]).is_err());
        assert!(Args::parse(vec!["--static-only".into(), "--static-only".into()]).is_err());
        let parsed = Args::parse(vec!["image".into(), "--version=20260921.0".into()]).unwrap();
        assert_eq!(parsed.value("version"), Some("20260921.0"));
    }
}
