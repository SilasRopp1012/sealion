import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  images: {
    unoptimized: true
  },
  // Add this for Netlify
  target: 'serverless'
};

export default nextConfig; 