import type { NextConfig } from "next";

for (const name of Object.keys(process.env)) {
  if (/^NEXT_PUBLIC_.*(?:SECRET|PASSWORD|PRIVATE_KEY|ACCESS_TOKEN|REFRESH_TOKEN|API_KEY)$/i.test(name)) {
    throw new Error(`Secret-like configuration must not be exposed to browsers: ${name}`);
  }
}

const nextConfig: NextConfig = {
  productionBrowserSourceMaps: false,
  poweredByHeader: false,
  ...(process.env.NEXT_DIST_DIR ? { distDir: process.env.NEXT_DIST_DIR } : {}),
  transpilePackages: ["@noirly-dev/ui"],
};

export default nextConfig;
