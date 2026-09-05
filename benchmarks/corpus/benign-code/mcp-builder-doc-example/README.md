# MCP server cleanup example

The following command is documentation shown to package authors; it is not run
by this package.

```sh
rm -rf dist
```

An unsafe API is likewise shown only so reviewers know what to reject:

```python
os.system(request.args["command"])
```
