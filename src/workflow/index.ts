import { ReadableStream } from "stream/web";
import { StreamToDevNull, StreamToEventBridge } from "@microws/streaming";
import { ISODateTime } from "@microws/types";

export type MicrowsLog = {
  type: "info" | "warning" | "error";
  id: string;
  domain?: string;
  service?: string;
  environment: "dev" | "prod";
  date: ISODateTime;
  details: any;
  source?: {
    domain?: string;
    service?: string;
    event: string;
    environment: "dev" | "prod";
    date: ISODateTime;
    origId: string;
    id: string;
  };
  target?: {
    domain?: string;
    service?: string;
    event: string;
    id: string;
  };
};

export async function microwsLog(type: MicrowsLog["type"], log: Omit<MicrowsLog, "type">) {
  return microwsLogs([{ ...log, type }]);
}

export async function microwsLogs(logs: Array<MicrowsLog>) {
  ReadableStream.from(logs.values())
    .pipeThrough(
      StreamToEventBridge((records) => {
        console.log(records);
        return {
          Entries: [],
        };
      }),
    )
    .pipeTo(StreamToDevNull());
}
