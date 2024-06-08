import { StreamFromDynamoDB } from "@microws/streaming";
import { ISO8601Date, ISODateTime } from "@microws/types";
import { MicrowsModuleDB } from "@microws/types/server";
import { WritableStream } from "node:stream/web";

const componentVersions = new Map<string, MicrowsModuleDB>();

let componentListeners = new Set<(id: string, entry: MicrowsModuleDB) => void>();
function updateComponent(id: string, entry: MicrowsModuleDB) {
  componentVersions.set(entry.id, entry);
  componentListeners.forEach((listener) => {
    listener(entry.id, entry);
  });
}
export async function start() {
  await new Promise(async (res, rej) => {
    try {
      await StreamFromDynamoDB<MicrowsModuleDB>(
        {
          watch: true,
          keys: ["TypePK", "TypeSK", "PK", "SK"],
        },
        {
          IndexName: "Type",
          TableName: process.env.MICROWS_TABLE,
          KeyConditionExpression: `TypePK=:microwsModule`,
          ExpressionAttributeValues: {
            ":microwsModule": "MicrowsModule",
          },
        },
      ).pipeTo(
        new WritableStream({
          write(entry) {
            if ("_microws" in entry) {
              res(entry);
            } else {
              updateComponent(entry.id, entry);
            }
          },
        }),
      );
    } catch (e) {
      rej(new Error(e.message));
    }
  });
}

export async function getModuleVersionsTable(user: {
  id: string;
  group: string;
  type: "developer" | "qa" | "deploy" | "general";
  context?: {
    [key: string]: string;
  };
}) {
  return new Map<
    string,
    {
      hash: string;
      time: ISODateTime;
    }
  >(
    Array.from(componentVersions.values())
      .map((c): null | [string, { hash: string; time: ISO8601Date }] => {
        let userVersion = c[user.type];
        if (!userVersion || userVersion.version == "None") {
          return null;
        }
        return [
          c.id,
          {
            hash: c[user.type].version,
            time: c[user.type].date,
          },
        ];
      })
      .filter(Boolean),
  );
}
