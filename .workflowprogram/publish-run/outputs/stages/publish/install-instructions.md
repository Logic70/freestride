# Target Workflow Plugin Install Instructions

- Repository: `https://github.com/Logic70/freestride`
- Marketplace: `target-workflow-plugins`
- Plugin: `freestride`
- Version: `0.1.1`
- Runtime mode: `workflowprogram_dependency`
- GitHub publish status: `PASS`

## Install

Install WorkflowProgram first:

```text
/plugin marketplace add logic70-plugins https://github.com/Logic70/WorkflowProgram.git
/plugin install workflowprogram-cn@logic70-plugins
```

Install the target workflow plugin:

```text
/plugin marketplace add target-workflow-plugins https://github.com/Logic70/freestride
/plugin install freestride@target-workflow-plugins
```

## Update

```text
/plugin update freestride@target-workflow-plugins
```
