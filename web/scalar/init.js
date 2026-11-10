// The page of /admin/v1/docs: Scalar's API reference on docs.json, beside the
// page. A file of its own, for the CSP of the page has no inline script. Nothing
// of what Scalar's own services offer: no telemetry, no fonts of
// fonts.scalar.com, no proxy, no AI agent, no MCP, no developer tools (deploy,
// share, SDKs); the CSP would refuse their requests anyway (connect-src and
// font-src 'self'). The client that tries a request stays: it calls the
// dispatcher itself.
Scalar.createApiReference("#app", {
  url: "docs.json",
  telemetry: false,
  withDefaultFonts: false,
  proxyUrl: "",
  agent: { disabled: true },
  mcp: { disabled: true },
  showDeveloperTools: "never",
});
