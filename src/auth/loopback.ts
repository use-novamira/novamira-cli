// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { CliError } from "../errors.js";
import { stateMatches } from "./pkce.js";

export const CALLBACK_PATH = "/callback";

export interface AuthorizationCallback {
  readonly code?: string;
  readonly error?: string;
}

export interface CallbackSession {
  readonly redirectUri: string;
  wait(
    expectedState: string,
    timeoutMs: number,
  ): Promise<AuthorizationCallback>;
  close(): Promise<void>;
}

export interface CallbackFactory {
  start(): Promise<CallbackSession>;
}

export class LoopbackCallbackFactory implements CallbackFactory {
  async start(): Promise<CallbackSession> {
    return new Promise((resolve, reject) => {
      const server = createServer();
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (address === null || typeof address === "string") {
          server.close();
          reject(
            new CliError("internal_error", "Loopback listener did not bind."),
          );
          return;
        }
        server.removeListener("error", reject);
        resolve(new LoopbackCallbackSession(server, address.port));
      });
    });
  }
}

class LoopbackCallbackSession implements CallbackSession {
  readonly redirectUri: string;
  private waiting = false;

  constructor(
    private readonly server: Server,
    port: number,
  ) {
    this.redirectUri = `http://127.0.0.1:${String(port)}${CALLBACK_PATH}`;
  }

  async wait(
    expectedState: string,
    timeoutMs: number,
  ): Promise<AuthorizationCallback> {
    if (this.waiting)
      throw new CliError(
        "internal_error",
        "Callback listener is already waiting.",
      );
    this.waiting = true;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(
          new CliError("auth_denied", "Authorization callback timed out."),
        );
      }, timeoutMs);
      const onRequest = (
        request: IncomingMessage,
        response: ServerResponse,
      ) => {
        try {
          const callback = validateCallbackUrl(
            new URL(request.url ?? "", this.redirectUri).toString(),
            this.redirectUri,
            expectedState,
          );
          response.writeHead(200, {
            "content-type": "text/plain; charset=utf-8",
          });
          response.end("Authorization completed. You may close this tab.\n");
          cleanup();
          resolve(callback);
        } catch (error) {
          response.writeHead(400, {
            "content-type": "text/plain; charset=utf-8",
          });
          response.end("Authorization callback was rejected.\n");
          cleanup();
          reject(
            error instanceof Error
              ? error
              : new Error("Authorization callback failed.", { cause: error }),
          );
        }
      };
      const cleanup = () => {
        clearTimeout(timer);
        this.server.removeListener("request", onRequest);
      };
      this.server.on("request", onRequest);
    });
  }

  async close(): Promise<void> {
    if (!this.server.listening) return;
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => {
        if (error === undefined) resolve();
        else
          reject(
            new Error("Loopback listener failed to close.", { cause: error }),
          );
      });
      this.server.closeAllConnections();
    });
  }
}

export function validateCallbackUrl(
  value: string,
  redirectUri: string,
  expectedState: string,
): AuthorizationCallback {
  let callback: URL;
  let expected: URL;
  try {
    callback = new URL(value);
    expected = new URL(redirectUri);
  } catch (cause) {
    throw new CliError(
      "auth_denied",
      "Authorization callback URL is invalid.",
      {
        cause,
      },
    );
  }
  if (
    callback.origin !== expected.origin ||
    callback.pathname !== expected.pathname ||
    callback.username !== "" ||
    callback.password !== "" ||
    callback.hash !== ""
  )
    throw new CliError(
      "auth_denied",
      "Authorization callback path is invalid.",
    );
  const states = callback.searchParams.getAll("state");
  const errors = callback.searchParams.getAll("error");
  const codes = callback.searchParams.getAll("code");
  if (
    states.length !== 1 ||
    errors.length > 1 ||
    codes.length > 1 ||
    (errors.length === 1 && codes.length === 1) ||
    !stateMatches(expectedState, states[0] ?? "")
  )
    throw new CliError(
      "auth_denied",
      "Authorization callback state is invalid.",
    );
  const error = errors[0];
  if (error !== undefined && error !== "") return { error };
  const code = codes[0];
  if (code === undefined || code === "")
    throw new CliError("auth_denied", "Authorization callback has no code.");
  return { code };
}
