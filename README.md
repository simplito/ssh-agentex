# ssh-agentex

Rust-based SSH agent that prevents hijacking by requiring confirmation for each signature request and supports multiple sub-agents for managing diverse keys.

```
Usage: ssh-agentex [-p] [ADDITIONAL_SUBAGENT_PATH]...

  -p, --permissive    do not show confirmation dialog
                      only useful when additional subagents are used
  -h, --help          this usage help

Always proxies the current agent pointed by SSH_AUTH_SOCK environment variable.
You can specify additional agents that should be queried in case when you want
to use keys from multiple sources.
In case multiple agents are used all client requests (beside identities request)
are processed sequentially until receiving first successfull response from sub agent.
```

