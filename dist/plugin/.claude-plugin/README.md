# FreeSTRIDE

This Claude Code plugin was packaged from a WorkflowProgram-generated target workflow.

## Install This Plugin

Add this workflow plugin marketplace, then install the plugin:

```text
/plugin marketplace add target-workflow-plugins https://github.com/Logic70/freestride
/plugin install freestride@target-workflow-plugins
```

## Runtime Mode

- `workflowprogram_dependency`
- Install WorkflowProgram first:

```text
/plugin marketplace add logic70-plugins https://github.com/Logic70/WorkflowProgram.git
/plugin install workflowprogram-cn@logic70-plugins
```

## Python Dependencies

Install target workflow Python dependencies before running scripts that render reports or validate workflow outputs:

```text
python3 -m pip install -r requirements.txt
```

Declared packages:

- `pyyaml`
- `jinja2`
