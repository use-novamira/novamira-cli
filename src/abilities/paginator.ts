// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CliError } from "../errors.js";

export const ABILITY_PAGE_SIZE = 100;
export const MAX_ABILITY_PAGES = 1_000;

interface NamedRecord {
  readonly name: string;
}

interface PageResponse {
  readonly data: unknown;
  readonly headers: Headers;
}

interface WordPressPaginatorOptions<T extends NamedRecord> {
  readonly endpoint: URL;
  readonly expectedOrigin: string;
  readonly fetchPage: (url: URL) => Promise<PageResponse>;
  readonly parseRecord: (value: unknown) => T;
}

export class WordPressPaginator<T extends NamedRecord> {
  private readonly endpoint: URL;
  private readonly expectedOrigin: string;
  private readonly fetchPage: WordPressPaginatorOptions<T>["fetchPage"];
  private readonly parseRecord: WordPressPaginatorOptions<T>["parseRecord"];

  constructor(options: WordPressPaginatorOptions<T>) {
    this.endpoint = new URL(options.endpoint);
    this.expectedOrigin = options.expectedOrigin;
    this.fetchPage = options.fetchPage;
    this.parseRecord = options.parseRecord;
  }

  async collect(): Promise<T[]> {
    const records: T[] = [];
    const names = new Set<string>();
    let expectedTotal: number | undefined;
    let pagination: "total" | "link" | undefined;

    for (let page = 1; page <= MAX_ABILITY_PAGES; page += 1) {
      const response = await this.fetchPage(this.pageUrl(page));
      if (!Array.isArray(response.data))
        throw unsupported("The WordPress Ability list is invalid.");
      const pageRecords = response.data.map(this.parseRecord);
      for (const record of pageRecords) {
        if (names.has(record.name))
          throw unsupported(
            "The WordPress Ability catalog changed during discovery.",
          );
        names.add(record.name);
        records.push(record);
      }

      const total = totalPages(response.headers.get("x-wp-totalpages"));
      const linkHeader = response.headers.get("link");
      pagination ??=
        total === undefined
          ? linkHeader === null
            ? undefined
            : "link"
          : "total";
      if (pagination === undefined)
        throw unsupported(
          "The WordPress Ability list lacks pagination metadata.",
        );
      if (pagination === "total" && total === undefined)
        throw unsupported(
          "The WordPress Ability page count changed during discovery.",
        );
      if (pagination === "link" && total !== undefined)
        throw unsupported(
          "The WordPress Ability pagination method changed during discovery.",
        );
      if (total !== undefined) {
        if (expectedTotal !== undefined && total !== expectedTotal)
          throw unsupported(
            "The WordPress Ability page count changed during discovery.",
          );
        expectedTotal = total;
        if (total > MAX_ABILITY_PAGES)
          throw unsupported(
            "The WordPress Ability catalog exceeds the page safety limit.",
          );
        if (total === 0 && (page !== 1 || pageRecords.length !== 0))
          throw unsupported(
            "The WordPress Ability page count is inconsistent.",
          );
        if (total > 0 && page > total)
          throw unsupported(
            "The WordPress Ability page count is inconsistent.",
          );
      }

      const next = linkHeader === null ? undefined : nextLink(linkHeader);
      if (next !== undefined) this.assertNextPage(next, page + 1);
      if (
        expectedTotal !== undefined &&
        next !== undefined &&
        page >= expectedTotal
      )
        throw unsupported("Ability pagination metadata is inconsistent.");

      if (expectedTotal !== undefined) {
        if (expectedTotal === 0 || page === expectedTotal) return records;
        continue;
      }
      if (next === undefined) return records;
    }
    throw unsupported(
      "The WordPress Ability catalog exceeds the page safety limit.",
    );
  }

  private pageUrl(page: number): URL {
    const url = new URL(this.endpoint);
    url.searchParams.set("per_page", String(ABILITY_PAGE_SIZE));
    url.searchParams.set("page", String(page));
    return url;
  }

  private assertNextPage(value: string, expectedPage: number): void {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw unsupported("Ability pagination contains an invalid next link.");
    }
    if (
      url.origin !== this.expectedOrigin ||
      url.pathname !== this.endpoint.pathname ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== "" ||
      url.searchParams.get("rest_route") !==
        this.endpoint.searchParams.get("rest_route") ||
      url.searchParams.get("page") !== String(expectedPage) ||
      url.searchParams.get("per_page") !== String(ABILITY_PAGE_SIZE)
    )
      throw unsupported(
        "Ability pagination contains an unsafe or looping next link.",
      );
  }
}

function totalPages(value: string | null): number | undefined {
  if (value === null) return undefined;
  if (!/^(0|[1-9]\d*)$/.test(value))
    throw unsupported("The WordPress Ability page count is invalid.");
  const total = Number(value);
  if (!Number.isSafeInteger(total))
    throw unsupported("The WordPress Ability page count is invalid.");
  return total;
}

function nextLink(value: string): string | undefined {
  if (value.trim() === "")
    throw unsupported("Ability pagination Link metadata is invalid.");
  let next: string | undefined;
  for (const part of value.split(/,(?=\s*<)/)) {
    const match = /^\s*<([^>]+)>\s*((?:;\s*[^;]+)*)\s*$/.exec(part);
    if (match === null)
      throw unsupported("Ability pagination Link metadata is invalid.");
    const parameters = match[2] ?? "";
    const relation = /(?:^|;)\s*rel\s*=\s*(?:"([^"]*)"|([^;\s]+))/i.exec(
      parameters,
    );
    const relations = (relation?.[1] ?? relation?.[2] ?? "").split(/\s+/);
    if (!relations.includes("next")) continue;
    if (next !== undefined)
      throw unsupported("Ability pagination contains multiple next links.");
    next = match[1];
  }
  return next;
}

function unsupported(message: string): CliError {
  return new CliError("server_unsupported", message);
}
