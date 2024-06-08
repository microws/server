import { EvidentlyClient, EvaluateFeatureCommand, BatchEvaluateFeatureCommand } from "@aws-sdk/client-evidently";
import { ISO8601Date } from "@microws/types";

let evidentlyClient = new EvidentlyClient({
  endpoint: "http://localhost:2772",
  disableHostPrefix: true,
});
const componentNames = new Set<string>();
const componentVersions = new Map<
  string,
  {
    trunk: string | "None";
    beta: string | "None";
    release: string | "None";
    history_1: string | "None";
    history_2: string | "None";
  }
>();

const Project = process.env.APP_CONFIG?.split(/\//g).pop();

let lastEvidentlyVersion = null;
async function checkEvidentlyVersion() {
  if (!process.env.APP_CONFIG) return;
  if (global.evidentlyCheckTimeout) {
    clearTimeout(global.evidentlyCheckTimeout);
  }
  try {
    let r = await fetch("http://localhost:2772/" + process.env.APP_CONFIG, {
      method: "GET",
    });

    let currentVersion = r.headers.get("configuration-version");

    if (currentVersion !== lastEvidentlyVersion) {
      lastEvidentlyVersion = currentVersion;

      let result = (await r.json()) as { project: string; features: Array<any> };
      Object.values(result.features)
        .filter((r) => r.name.match(/^[a-zA-z]*Module_/))
        .forEach((r) => {
          componentVersions.set(r.name, r.variations);
          componentNames.add(r.name);
        });
    }
  } catch (e) {
    console.log(e);
  }
  global.evidentlyCheckTimeout = setTimeout(checkEvidentlyVersion, 1_000);
}

export async function getModuleVersions(
  prefix: string,
  user: {
    id: string;
    group: string;
    type: "trunk" | "beta" | "release";
    context?: {
      [key: string]: string;
    };
  },
) {
  if (!lastEvidentlyVersion) {
    await checkEvidentlyVersion();
  }
  let myVersions = new Map<string, { hash: string; time: ISO8601Date }>();
  let components = Array.from(componentNames.values());

  let batches = [];
  for (let i = 0; i < components.length; i += 20) {
    batches.push(
      evidentlyClient
        .send(
          new BatchEvaluateFeatureCommand({
            project: Project,
            requests: components.slice(i, 20).map((feature) => {
              return {
                entityId: user.id,
                feature: feature,
                evaluationContext: JSON.stringify(user.context || {}),
              };
            }),
          }),
        )
        .then(({ results }) => {
          results.forEach((r, i) => {
            let name = r.feature.split(/\//g).pop();
            if (!name.match(new RegExp(`Module_${prefix}-`, "i")) && !name.startsWith("Module_shared")) {
              return;
            }
            if (r.value.stringValue != "None" && r.reason !== "DEFAULT") {
              let [hash, time] = r.value.stringValue.split(/[\s*\u00A0]*\|[\s*\u00A0]*/);
              myVersions.set(name.replace("Module_", ""), {
                hash,
                time,
              });
            } else if (componentVersions.get(name)?.[user.type]) {
              let [hash, time] = componentVersions.get(name)[user.type].split(/[\s*\u00A0]*\|[\s*\u00A0]*/) || [];
              myVersions.set(name.replace("Module_", ""), {
                hash,
                time,
              });
            }
          });
        }),
    );
  }
  await Promise.all(batches);
  return myVersions;
}

export async function getFeature(
  flag: string,
  user: {
    id: string;
    group: string;
    type: "trunk" | "beta" | "release";
    context?: {
      [key: string]: string;
    };
  },
) {
  try {
    let result = await evidentlyClient.send(
      new EvaluateFeatureCommand({
        project: Project,
        feature: flag,
        entityId: user.id,
        evaluationContext: JSON.stringify(user.context),
      }),
    );
    return {
      id: user.id,
      reason: result.reason,
      variation: result.variation,
      value: Object.entries(result.value).reduce((acc, [name, value]) => {
        return value;
      }, null),
    };
  } catch (e) {
    return {
      id: user.id,
      reason: "MISSING",
      value: "",
      variation: "NONE",
    };
  }
}
