import { CognitoJwtVerifier } from "aws-jwt-verify";
import { CognitoIdTokenPayload } from "aws-jwt-verify/jwt-model";
import { NextFunction, Request, RequestHandler, Response, Router, RouterOptions } from "express";
import { PathParams, IRouter, IRouterMatcher } from "express-serve-static-core";
import { binary_to_base58 } from "base58-js";
import { GuidString } from "@microws/types";
import { s3Client } from "@microws/aws";
import { getFeature, getModuleVersions } from "./evidently.js";

export type UserParseOutput = {
  evidentlyConfig: {
    id: string;
    group: string;
    type: "trunk" | "release" | "beta";
    context: Record<string, string>;
  };
  frontEndConfig: Record<string, any>;
};

function parseUUID(uuid: string) {
  let v: number;
  const arr = new Uint8Array(16); // Parse ########-....-....-....-............

  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = (v >>> 16) & 0xff;
  arr[2] = (v >>> 8) & 0xff;
  arr[3] = v & 0xff; // Parse ........-####-....-....-............

  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 0xff; // Parse ........-....-####-....-............

  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 0xff; // Parse ........-....-....-####-............

  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 0xff; // Parse ........-....-....-....-############
  // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

  arr[10] = ((v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000) & 0xff;
  arr[11] = (v / 0x100000000) & 0xff;
  arr[12] = (v >>> 24) & 0xff;
  arr[13] = (v >>> 16) & 0xff;
  arr[14] = (v >>> 8) & 0xff;
  arr[15] = v & 0xff;
  return arr;
}

export interface APIInterface {
  post: any;
  output: any;
  params: any;
  get: any;
  locals: {
    user: UserIdToken;
    [key: string]: any;
  };
}
export interface MicrowsIRouterMatcher<
  T,
  Method extends "all" | "get" | "post" | "put" | "delete" | "patch" | "options" | "head" = any,
> extends IRouterMatcher<T, Method> {
  <Request extends Partial<APIInterface>>(
    path: PathParams,
    ...handlers: Array<
      RequestHandler<Request["params"], Request["output"], Request["post"], Request["get"], Request["locals"]>
    >
  ): T;
}

export interface MicrowsRouter extends IRouter {
  get: MicrowsIRouterMatcher<this, "get">;
  post: MicrowsIRouterMatcher<this, "post">;
  all: MicrowsIRouterMatcher<this, "all">;
  put: MicrowsIRouterMatcher<this, "put">;
  delete: MicrowsIRouterMatcher<this, "delete">;
  patch: MicrowsIRouterMatcher<this, "patch">;
  options: MicrowsIRouterMatcher<this, "options">;
  head: MicrowsIRouterMatcher<this, "head">;
}

export function MicrowsRouter(options?: RouterOptions): MicrowsRouter {
  return Router(options);
}

export type UserIdToken = {
  id: string;
  email: string;
  name: string;
  picture: string;
  fName: string;
  lName: string;
  locale: string;
};
export function parseAuthentication(
  userPoolId: string,
  userPoolClientId: string,
  {
    formatUser,
  }: {
    formatUser?: (payload: CognitoIdTokenPayload) => UserIdToken;
  } = {},
) {
  const cognitoVerifier = CognitoJwtVerifier.create({
    userPoolId: userPoolId,
    clientId: userPoolClientId,
    tokenUse: "id",
  });
  if (!formatUser) {
    formatUser = (payload) => {
      return {
        id: (payload.id || null) as GuidString,
        cognitoUserName: payload["cognito:username"],
        cognitoId: binary_to_base58(parseUUID(payload.sub)),
        email: payload.email?.toString(),
        name: payload.name?.toString(),
        picture: payload.picture?.toString(),
        fName: payload.given_name?.toString(),
        lName: payload.family_name?.toString(),
        locale: payload.locale?.toString(),
        groups: payload["cognito:groups"] || [],
      };
    };
  }

  return async function (req: Request, res: Response, next: NextFunction) {
    if (req.header("Authorization")) {
      let token = req.header("Authorization").split(/ /)[1];
      res.locals.user = formatUser(await cognitoVerifier.verify(token));
    } else {
    }
    next();
  };
}
export function requireAuthentication(req: Request, res: Response, next: NextFunction) {
  if (!res.locals.user) {
    throw new BackendAPIError401();
  } else {
    next();
  }
}
export function requireSanitization(req: Request, res: Response, next: NextFunction) {
  res.locals._unsanitizedBody = req.body;
  res.locals._unsanitizedQuery = req.query;
  delete req.body;
  delete req.query;
  next();
}
export const Sanitize = {
  int: () => {
    return {
      test: (value: number, name: string) => {
        if (!Number.isSafeInteger(value)) {
          throw new Error(`${value} is not a correct int(${name})`);
        }
      },
    };
  },
  keyword: () => {
    return {
      test: (value: string, name: string) => {
        if (typeof value !== "string" || !value.match(/^[a-zA-Z][a-zA-Z0-9_\-]*$/)) {
          throw new Error(`${value} is an invalid keyword(${name})`);
        }
      },
      value: (value: string) => {
        return value.trim();
      },
    };
  },
  text: () => {
    return {
      test: (value: string, name: string) => {
        if (typeof value !== "string" || !value.match(/^[^\p{C}\p{Zl}\p{Zp}]*$/)) {
          throw new Error(`${value} is invalid text(${name})`);
        }
      },
      value: (value: string) => {
        return value.trim();
      },
    };
  },
  in: (values: Array<any>) => {
    return {
      test: (value: number, name: string) => {
        if (!values.includes(value)) {
          throw new Error(`${value} is not in(${name}, ${values.join(",")})`);
        }
      },
    };
  },
};
// Record<string, (...any)=>{
//   test: (value:any, args: any)=>boolean,
//   value: (value:any, args: any)=>boolean,
// }
export function sanitize(rules: any) {
  const sanitizer = {
    get(target: Record<string, any>, prop: string) {
      if (!(prop in rules)) {
        console.log("No Santization rule defined for ", prop);
        throw new Error("Invalid Property " + prop);
      } else {
        try {
          rules[prop].test?.(target[prop], prop);
        } catch (e) {
          e.stack = "";
          throw e;
        }
      }
      return target[prop];
    },
  };

  return (req: Request, res: Response, next: NextFunction) => {
    res.locals._unsanitizedParams = { ...req.params };
    req.body = new Proxy(res.locals._unsanitizedBody, sanitizer);
    req.params = new Proxy(res.locals._unsanitizedParams, sanitizer);
    req.query = new Proxy(res.locals._unsanitizedQuery, sanitizer);
    next();
  };
}

export function requireGroup(group: string) {
  return function (req: Request, res: Response, next: NextFunction) {
    if (!res.locals.user || !res.locals.user?.groups?.includes(group)) {
      throw new BackendAPIError401();
    } else {
      next();
    }
  };
}

export default class BaseError extends Error {
  httpCode: number;
  code: number;
  retryable: boolean;
  errors: any[];
  constructor(code: number, message: string, retryable: boolean = false, status: number = 400) {
    super(message || "Not Found");
    this.code = code;
    this.httpCode = status;
    this.retryable = retryable;
    this.name = "Error";
  }
}
export enum BackendAPIErrorType {
  Missing = 1,
  Code404 = 404,
  Code401 = 401,
  Code400 = 400,
}
export class NotLoggedInError extends BaseError {
  constructor(message?: string) {
    super(400, message, false, 404);
    this.name = "NotLoggedIn";
  }
}
export class BackendAPIError extends BaseError {
  constructor(code: number, message: string, retryable: boolean = false, status: number = 400, errors: any[] = null) {
    super(code, message, retryable, status);
    this.name = "BackendAPIError";
    this.errors = errors;
  }
}
export class BackendAPIError404 extends BackendAPIError {
  constructor(message?: string) {
    super(BackendAPIErrorType.Code404, message || "Not Found", false, 404);
  }
}

export class BackendAPIError400 extends BackendAPIError {
  constructor(message?: string, errors: any[] = null) {
    super(BackendAPIErrorType.Code400, message || "Bad Request", false, 400, errors);
  }
}
export class BackendAPIError401 extends BackendAPIError {
  constructor(message?: string, errors: any[] = null) {
    super(BackendAPIErrorType.Code401, message || "Unauthorized Response", false, 401, errors);
  }
}

let cache = new Map<string, Promise<string>>();
export function staticCache(bucket: string) {
  return (file: string): Promise<string> => {
    if (!cache.has(file)) {
      console.log("Fetching Static: " + file);
      console.time("Fetched Static: " + file);
      cache.set(
        file,
        s3Client
          .get({
            Bucket: bucket,
            Key: file,
          })
          .then((r) => {
            console.timeEnd("Fetched Static: " + file);
            return r.Body.transformToString();
          }),
      );
    }
    return cache.get(file);
  };
}
export function handleHtmlRequest({
  app,
  staticBucket,
  ignoreRoutes,
  webConfig,
}: {
  app: string;
  staticBucket: string;
  ignoreRoutes?: Array<string>;
  webConfig: (
    locals: any,
  ) =>
    | Promise<Record<string, string | number | boolean | Set<any> | Map<any, any>>>
    | Record<string, string | number | boolean | Set<any> | Map<any, any>>;
}) {
  let htmlCache = staticCache(staticBucket);
  let router = MicrowsRouter();
  router.get(
    "*",
    async (req, res, next) => {
      let skip = ["api", "static", "media", ".well-known"].concat(ignoreRoutes || []).reduce((acc, value) => {
        return acc || req.url.startsWith("/" + value) || req.url.startsWith(value);
      }, false);
      if (skip) {
        next("route");
      } else {
        next();
      }
    },
    async (req: Request, res: Response, next: NextFunction) => {
      if (req.url.match(/api/) || req.url.match(/media/) || req.url.match(/static/)) return next();
      let myVersions = await getModuleVersions(app, res.locals.evidentlyConfig);
      let htmlName = app.toLowerCase() + "-html";
      let htmlHashCode = myVersions.get(htmlName).hash;
      let html = res.locals.html || (await htmlCache(`static/${htmlName}-${htmlHashCode}.html`));

      html = html
        .replace(new RegExp(`src="(shared.*)-(\\[HASH\\]).js"`, "i"), (match: string, p1: string, p2: string) => {
          return `src="/static/${p1}-${myVersions.get(p1).hash}.js"`;
        })
        .replace(
          /__CONFIG__/,
          JSON.stringify(
            JSON.stringify({ ...(await webConfig(res.locals)), components: myVersions }, (key, value) => {
              if (value instanceof Map) {
                return {
                  dataType: "Map",
                  value: Array.from(value),
                };
              } else if (value instanceof Set) {
                return {
                  dataType: "Set",
                  value: Array.from(value),
                };
              } else {
                return value;
              }
            }),
          ),
        );
      res.send(html);
    },
  );
  return router;
}

export const flagRouter = MicrowsRouter({ mergeParams: true });
flagRouter.use(requireSanitization);
flagRouter.get(
  "/:flag",
  sanitize({
    flag: Sanitize.keyword(),
  }),
  async (req, res) => {
    res.json(await getFeature(req.params.flag, res.locals.evidentlyConfig));
  },
);

export function requireFeature({
  flag,
  value,
  variation,
}: {
  flag: string;
  value?: string | number | boolean | Array<string | number | boolean>;
  variation?: string | Array<string>;
}) {
  let values: Set<string | boolean | number> = new Set();
  let variations: Set<string | boolean | number> = new Set();
  if (value !== undefined) {
    if (Array.isArray(value)) {
      values = new Set(value);
    } else {
      values = new Set([value]);
    }
  }
  if (variation !== undefined) {
    if (Array.isArray(variation)) {
      variations = new Set(variation);
    } else {
      variations = new Set([variation]);
    }
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    let result = await getFeature(flag, res.locals.evidentlyConfig);
    if (values.has(result.value) || variations.has(result.variation)) {
      next();
    } else {
      next("route");
    }
  };
}
