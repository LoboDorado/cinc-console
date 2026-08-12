import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  // ldapjs does raw TLS socket + BER binary parsing that Next's production
  // bundler mishandles: it works under `next dev` but crashes at runtime in
  // a `next build` bundle with "Cannot read properties of undefined
  // (reading 'toLowerCase')" deep inside a minified chunk's TLSSocket data
  // handler, on every LDAP bind attempt. Treat it as a real Node require at
  // runtime instead of bundling/transforming it.
  serverExternalPackages: ["ldapjs"],
};

export default nextConfig;
