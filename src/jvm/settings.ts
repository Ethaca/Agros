import { dbImageOf, type Config } from "../config.js";

/** The JVM-related config fields (target.runtime/build, container images, db, auth) as the runner uses them. */

export type Runtime = "node" | "jvm";
export type DbSettings = NonNullable<Config["db"]> & { image: string };
export type AuthSettings = Pick<NonNullable<Config["auth"]>, "env" | "audience">;

export interface JvmSettings {
  runtime: Runtime;
  build?: string;
  buildImage?: string;
  sidecarImage?: string;
  /** Explicit app image (target.container.image); default is detected from the JDK version. */
  appImage?: string;
  db?: DbSettings;
  auth?: AuthSettings;
}

export const runtimeOf = (cfg: Config): Runtime => cfg.target.runtime;

export function jvmSettings(cfg: Config): JvmSettings {
  const c = cfg.target.container;
  return {
    runtime: cfg.target.runtime,
    build: cfg.target.build,
    buildImage: c.buildImage,
    sidecarImage: c.sidecarImage,
    appImage: c.image,
    db: cfg.db ? { ...cfg.db, image: dbImageOf(cfg) } : undefined,
    auth: cfg.auth,
  };
}
