### Project Structure
centaur
├── Cargo.lock
├── Cargo.toml
├── config.toml
├── logs
├── README.md
├── rules
│   ├── admin
│   │   ├── crs
│   │   │   ├── *.conf
|   |   |   ├── *.data
│   │   └── crs-setup.conf
│   ├── api
│   │   ├── crs
│   │   │   ├── *.data
│   │   │   ├── *.conf
│   │   └── crs-setup.conf
│   ├── default
│   │   ├── crs
│   │   │   ├── *.data
│   │   │   ├── *.conf
│   │   └── crs-setup.conf
│   └── web
│       ├── crs
│       │   ├── *.data
│       │   ├── *.conf
│       └── crs-setup.conf
└── src
    ├── cli
    │   ├── cli.rs
    │   └── mod.rs
    ├── config
    │   ├── config.rs
    │   └── mod.rs
    ├── logger
    │   ├── logger.rs
    │   └── mod.rs
    ├── main.rs
    ├── proxy
    │   ├── mod.rs
    │   └── proxy.rs
    ├── waf
    │   ├── engine.rs
    │   ├── mod.rs
    │   └── reloader.rs
    └── web
        ├── api.rs
        ├── mod.rs
        └── ui.rs