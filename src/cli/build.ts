// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-Present The Pepr Authors

import { execSync, execFileSync } from "child_process";
import { BuildOptions, BuildResult, analyzeMetafile, context } from "esbuild";
import { promises as fs } from "fs";
import { basename, dirname, extname, resolve } from "path";
import { createDockerfile } from "../lib/included-files";
import { Assets } from "../lib/assets";
import { dependencies, version } from "./init/templates";
import { RootCmd } from "./root";
import { peprFormat } from "./format";
import { Option } from "commander";
import { validateCapabilityNames, parseTimeout } from "../lib/helpers";
import { sanitizeResourceName } from "../sdk/sdk";
import { determineRbacMode } from "./build.helpers";
import { createDirectoryIfNotExists } from "../lib/filesystemService";
const peprTS = "pepr.ts";
let outputDir: string = "dist";
export type Reloader = (opts: BuildResult<BuildOptions>) => void | Promise<void>;

export default function (program: RootCmd) {
  program
    .command("build")
    .description("Build a Pepr Module for deployment")
    .option("-e, --entry-point [file]", "Specify the entry point file to build with.", peprTS)
    .option(
      "-n, --no-embed",
      "Disables embedding of deployment files into output module.  Useful when creating library modules intended solely for reuse/distribution via NPM.",
    )
    .option(
      "-i, --custom-image <custom-image>",
      "Custom Image: Use custom image for Admission and Watch Deployments.",
    )
    .option(
      "-r, --registry-info [<registry>/<username>]",
      "Registry Info: Image registry and username. Note: You must be signed into the registry",
    )
    .option("-o, --output-dir <output directory>", "Define where to place build output")
    .option(
      "--timeout <timeout>",
      "How long the API server should wait for a webhook to respond before treating the call as a failure",
      parseTimeout,
    )
    .option(
      "-v, --version <version>. Example: '0.27.3'",
      "The version of the Pepr image to use in the deployment manifests.",
    )
    .option(
      "--withPullSecret <imagePullSecret>",
      "Image Pull Secret: Use image pull secret for controller Deployment.",
    )

    .addOption(
      new Option(
        "--registry <GitHub|Iron Bank>",
        "Container registry: Choose container registry for deployment manifests. Can't be used with --custom-image.",
      ).choices(["GitHub", "Iron Bank"]),
    )

    .addOption(
      new Option(
        "-z, --zarf [manifest|chart]",
        "Zarf package type: manifest, chart (default: manifest)",
      )
        .choices(["manifest", "chart"])
        .default("manifest"),
    )
    .addOption(
      new Option("--rbac-mode [admin|scoped]", "Rbac Mode: admin, scoped (default: admin)").choices(
        ["admin", "scoped"],
      ),
    )
    .action(async opts => {
      // assign custom output directory if provided
      if (opts.outputDir) {
        outputDir = opts.outputDir;
        createDirectoryIfNotExists(outputDir).catch(error => {
          console.error(`Error creating output directory: ${error.message}`);
          process.exit(1);
        });
      }

      // Build the module
      const buildModuleResult = await buildModule(undefined, opts.entryPoint, opts.embed);
      if (buildModuleResult?.cfg && buildModuleResult.path && buildModuleResult.uuid) {
        const { cfg, path, uuid } = buildModuleResult;
        // Files to include in controller image for WASM support
        const { includedFiles } = cfg.pepr;

        let image: string = "";

        // Build Kubernetes manifests with custom image
        if (opts.customImage) {
          if (opts.registry) {
            console.error(`Custom Image and registry cannot be used together.`);
            process.exit(1);
          }
          image = opts.customImage;
        }

        // Check if there is a custom timeout defined
        if (opts.timeout !== undefined) {
          cfg.pepr.webhookTimeout = opts.timeout;
        }

        if (opts.registryInfo !== undefined) {
          console.info(`Including ${includedFiles.length} files in controller image.`);

          // for journey test to make sure the image is built
          image = `${opts.registryInfo}/custom-pepr-controller:${cfg.pepr.peprVersion}`;

          // only actually build/push if there are files to include
          if (includedFiles.length > 0) {
            await createDockerfile(cfg.pepr.peprVersion, cfg.description, includedFiles);
            execSync(`docker build --tag ${image} -f Dockerfile.controller .`, {
              stdio: "inherit",
            });
            execSync(`docker push ${image}`, { stdio: "inherit" });
          }
        }

        // If building without embedding, exit after building
        if (!opts.embed) {
          console.info(`✅ Module built successfully at ${path}`);
          return;
        }

        // set the image version if provided
        if (opts.version) {
          cfg.pepr.peprVersion = opts.version;
        }

        // Generate a secret for the module
        const assets = new Assets(
          {
            ...cfg.pepr,
            appVersion: cfg.version,
            description: cfg.description,
            // Can override the rbacMode with the CLI option
            rbacMode: determineRbacMode(opts, cfg),
          },
          path,
        );

        // If registry is set to Iron Bank, use Iron Bank image
        if (opts?.registry === "Iron Bank") {
          console.info(
            `\n\tThis command assumes the latest release. Pepr's Iron Bank image release cycle is dictated by renovate and is typically released a few days after the GitHub release.\n\tAs an alternative you may consider custom --custom-image to target a specific image and version.`,
          );
          image = `registry1.dso.mil/ironbank/opensource/defenseunicorns/pepr/controller:v${cfg.pepr.peprVersion}`;
        }

        // if image is a custom image, use that instead of the default
        if (image !== "") {
          assets.image = image;
        }

        // Ensure imagePullSecret is valid
        if (opts.withPullSecret) {
          if (sanitizeResourceName(opts.withPullSecret) !== opts.withPullSecret) {
            // https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names
            console.error(
              "Invalid imagePullSecret. Please provide a valid name as defined in RFC 1123.",
            );
            process.exit(1);
          }
        }

        const yamlFile = `pepr-module-${uuid}.yaml`;
        const chartPath = `${uuid}-chart`;
        const yamlPath = resolve(outputDir, yamlFile);
        const yaml = await assets.allYaml(opts.withPullSecret);

        try {
          // wait for capabilities to be loaded and test names
          validateCapabilityNames(assets.capabilities);
        } catch (e) {
          console.error(`Error loading capability:`, e);
          process.exit(1);
        }

        const zarfPath = resolve(outputDir, "zarf.yaml");

        let zarf = "";
        if (opts.zarf === "chart") {
          zarf = assets.zarfYamlChart(chartPath);
        } else {
          zarf = assets.zarfYaml(yamlFile);
        }
        await fs.writeFile(yamlPath, yaml);
        await fs.writeFile(zarfPath, zarf);

        await assets.generateHelmChart(outputDir);

        console.info(`✅ K8s resource for the module saved to ${yamlPath}`);
      }
    });
}

// Create a list of external libraries to exclude from the bundle, these are already stored in the container
const externalLibs = Object.keys(dependencies);

// Add the pepr library to the list of external libraries
externalLibs.push("pepr");

// Add the kubernetes client to the list of external libraries as it is pulled in by kubernetes-fluent-client
externalLibs.push("@kubernetes/client-node");

export async function loadModule(entryPoint = peprTS) {
  // Resolve path to the module / files
  const entryPointPath = resolve(".", entryPoint);
  const modulePath = dirname(entryPointPath);
  const cfgPath = resolve(modulePath, "package.json");

  // Ensure the module's package.json and entrypoint files exist
  try {
    await fs.access(cfgPath);
    await fs.access(entryPointPath);
  } catch (e) {
    console.error(
      `Could not find ${cfgPath} or ${entryPointPath} in the current directory. Please run this command from the root of your module's directory.`,
    );
    process.exit(1);
  }

  // Read the module's UUID from the package.json file
  const moduleText = await fs.readFile(cfgPath, { encoding: "utf-8" });
  const cfg = JSON.parse(moduleText);
  const { uuid } = cfg.pepr;
  const name = `pepr-${uuid}.js`;

  // Set the Pepr version from the current running version
  cfg.pepr.peprVersion = version;

  // Exit if the module's UUID could not be found
  if (!uuid) {
    throw new Error("Could not load the uuid in package.json");
  }

  return {
    cfg,
    entryPointPath,
    modulePath,
    name,
    path: resolve(outputDir, name),
    uuid,
  };
}

export async function buildModule(reloader?: Reloader, entryPoint = peprTS, embed = true) {
  try {
    const { cfg, modulePath, path, uuid } = await loadModule(entryPoint);

    const validFormat = await peprFormat(true);

    if (!validFormat) {
      console.log(
        "\x1b[33m%s\x1b[0m",
        "Formatting errors were found. The build will continue, but you may want to run `npx pepr format` to address any issues.",
      );
    }

    // Resolve node_modules folder (in support of npm workspaces!)
    const npmRoot = execFileSync("npm", ["root"]).toString().trim();

    // Run `tsc` to validate the module's types & output sourcemaps
    const args = ["--project", `${modulePath}/tsconfig.json`, "--outdir", outputDir];
    execFileSync(`${npmRoot}/.bin/tsc`, args);

    // Common build options for all builds
    const ctxCfg: BuildOptions = {
      bundle: true,
      entryPoints: [entryPoint],
      external: externalLibs,
      format: "cjs",
      keepNames: true,
      legalComments: "external",
      metafile: true,
      minify: true,
      outfile: path,
      plugins: [
        {
          name: "reload-server",
          setup(build) {
            build.onEnd(async r => {
              // Print the build size analysis
              if (r?.metafile) {
                console.log(await analyzeMetafile(r.metafile));
              }

              // If we're in dev mode, call the reloader function
              if (reloader) {
                await reloader(r);
              }
            });
          },
        },
      ],
      platform: "node",
      sourcemap: true,
      treeShaking: true,
    };

    if (reloader) {
      // Only minify the code if we're not in dev mode
      ctxCfg.minify = false;
    }

    // If not embedding (i.e. making a library module to be distro'd via NPM)
    if (!embed) {
      // Don't minify
      ctxCfg.minify = false;

      // Preserve the original file name
      ctxCfg.outfile = resolve(outputDir, basename(entryPoint, extname(entryPoint))) + ".js";

      // Don't bundle
      ctxCfg.packages = "external";

      // Don't tree shake
      ctxCfg.treeShaking = false;
    }

    const ctx = await context(ctxCfg);

    // If the reloader function is defined, watch the module for changes
    if (reloader) {
      await ctx.watch();
    } else {
      // Otherwise, just build the module once
      await ctx.rebuild();
      await ctx.dispose();
    }

    return { ctx, path, cfg, uuid };
  } catch (e) {
    console.error(`Error building module:`, e);

    if (!e.stdout) process.exit(1); // Exit with a non-zero exit code on any other error

    const out = e.stdout.toString() as string;
    const err = e.stderr.toString();

    console.log(out);
    console.error(err);

    // Check for version conflicts
    if (out.includes("Types have separate declarations of a private property '_name'.")) {
      // Try to find the conflicting package
      const pgkErrMatch = /error TS2322: .*? 'import\("\/.*?\/node_modules\/(.*?)\/node_modules/g;
      out.matchAll(pgkErrMatch);

      // Look for package conflict errors
      const conflicts = [...out.matchAll(pgkErrMatch)];

      // If the regex didn't match, leave a generic error
      if (conflicts.length < 1) {
        console.info(
          `\n\tOne or more imported Pepr Capabilities seem to be using an incompatible version of Pepr.\n\tTry updating your Pepr Capabilities to their latest versions.`,
          "Version Conflict",
        );
      }

      // Otherwise, loop through each conflicting package and print an error
      conflicts.forEach(match => {
        console.info(
          `\n\tPackage '${match[1]}' seems to be incompatible with your current version of Pepr.\n\tTry updating to the latest version.`,
          "Version Conflict",
        );
      });
    }
  }
}
