#!/usr/bin/env node
/**
 * Validate Docker Environment Variables
 * Issue #996: Ensures Dockerfile ARGs and docker-compose build.args match REQUIRED_ENV_VARS
 *
 * This script prevents silent failures where contract addresses are missing from
 * the Docker build configuration, which would result in empty strings being baked
 * into the production bundle.
 */

const fs = require('fs');
const path = require('path');

// Read the required env vars from stellar-config.ts
const stellarConfigPath = path.join(__dirname, '../frontend/src/lib/stellar-config.ts');
const stellarConfig = fs.readFileSync(stellarConfigPath, 'utf8');

// Extract REQUIRED_ENV_VARS array
const requiredVarsMatch = stellarConfig.match(/export const REQUIRED_ENV_VARS = \[([\s\S]*?)\] as const;/);
if (!requiredVarsMatch) {
  console.error('❌ Could not find REQUIRED_ENV_VARS in stellar-config.ts');
  process.exit(1);
}

const requiredVars = requiredVarsMatch[1]
  .split('\n')
  .map(line => line.trim())
  .filter(line => line.startsWith("'NEXT_PUBLIC_"))
  .map(line => line.replace(/[',]/g, ''));

console.log(`📋 Found ${requiredVars.length} required environment variables in REQUIRED_ENV_VARS`);

// Read Dockerfile
const dockerfilePath = path.join(__dirname, '../frontend/Dockerfile');
const dockerfile = fs.readFileSync(dockerfilePath, 'utf8');

// Extract ARG declarations
const argPattern = /^ARG (NEXT_PUBLIC_[A-Z_]+)$/gm;
const dockerfileArgs = [];
let match;
while ((match = argPattern.exec(dockerfile)) !== null) {
  dockerfileArgs.push(match[1]);
}

console.log(`🐳 Found ${dockerfileArgs.length} NEXT_PUBLIC_* ARG declarations in Dockerfile`);

// Read docker-compose.yml
const dockerComposePath = path.join(__dirname, '../docker-compose.yml');
const dockerCompose = fs.readFileSync(dockerComposePath, 'utf8');

// Extract build args from frontend service
const frontendBuildArgsMatch = dockerCompose.match(/frontend:[\s\S]*?args:([\s\S]*?)container_name:/);
if (!frontendBuildArgsMatch) {
  console.error('❌ Could not find frontend build.args in docker-compose.yml');
  process.exit(1);
}

const buildArgsSection = frontendBuildArgsMatch[1];
const buildArgsPattern = /(NEXT_PUBLIC_[A-Z_]+):/g;
const composeArgs = [];
while ((match = buildArgsPattern.exec(buildArgsSection)) !== null) {
  composeArgs.push(match[1]);
}

console.log(`📦 Found ${composeArgs.length} NEXT_PUBLIC_* build args in docker-compose.yml`);

// Validate: All required vars must be in Dockerfile ARGs
const missingInDockerfile = requiredVars.filter(v => !dockerfileArgs.includes(v));
const missingInCompose = requiredVars.filter(v => !composeArgs.includes(v));

// Also check for extras (not required but declared)
const extraInDockerfile = dockerfileArgs.filter(v => !requiredVars.includes(v));
const extraInCompose = composeArgs.filter(v => !requiredVars.includes(v));

let hasErrors = false;

if (missingInDockerfile.length > 0) {
  console.error('\n❌ MISSING in Dockerfile ARGs:');
  missingInDockerfile.forEach(v => console.error(`   - ${v}`));
  hasErrors = true;
}

if (missingInCompose.length > 0) {
  console.error('\n❌ MISSING in docker-compose.yml build.args:');
  missingInCompose.forEach(v => console.error(`   - ${v}`));
  hasErrors = true;
}

if (extraInDockerfile.length > 0) {
  console.warn('\n⚠️  EXTRA in Dockerfile ARGs (not in REQUIRED_ENV_VARS):');
  extraInDockerfile.forEach(v => console.warn(`   - ${v}`));
  // Note: This is just a warning, not an error
}

if (extraInCompose.length > 0) {
  console.warn('\n⚠️  EXTRA in docker-compose.yml build.args (not in REQUIRED_ENV_VARS):');
  extraInCompose.forEach(v => console.warn(`   - ${v}`));
  // Note: This is just a warning, not an error
}

if (!hasErrors) {
  console.log('\n✅ All required environment variables are declared in both Dockerfile and docker-compose.yml');
  console.log('✅ Docker build configuration is valid');
  process.exit(0);
} else {
  console.error('\n❌ Validation failed: Docker configuration does not match REQUIRED_ENV_VARS');
  console.error('\nTo fix this issue:');
  console.error('1. Add missing ARG declarations to frontend/Dockerfile');
  console.error('2. Add corresponding ENV statements in frontend/Dockerfile');
  console.error('3. Add missing build args to docker-compose.yml frontend service');
  console.error('\nRefer to the existing patterns in both files.');
  process.exit(1);
}
