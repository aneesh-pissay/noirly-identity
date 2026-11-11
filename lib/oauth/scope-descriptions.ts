import { SCOPE_MEANING, describeScopes } from "@/lib/account/app-scopes";
import { ApiResource, type ApiResourceDocument } from "@/models/ApiResource";

/**
 * What a set of scopes lets an app do, in words, including the scopes that
 * registered APIs define (lib/oauth/resources.ts): "Ledger: Read your
 * transactions". `resources` limits the lookup to those APIs (the ones this
 * request names); without it, any API defining the scope is used.
 */
export async function describeScopesWithApis(scopes: string[], resources?: string[]): Promise<string[]> {
  const own = scopes.filter((s) => s in SCOPE_MEANING);
  const others = scopes.filter((s) => !(s in SCOPE_MEANING));
  if (others.length === 0) return describeScopes(own);
  const filter = resources ? { identifier: { $in: resources } } : { "scopes.name": { $in: others } };
  const apis = await ApiResource.find(filter).select("name scopes").lean<ApiResourceDocument[]>();
  const lines = others.map((scope) => {
    for (const api of apis) {
      const defined = api.scopes.find((s) => s.name === scope);
      if (defined) return `${api.name}: ${defined.description || scope}`;
    }
    return scope;
  });
  return [...describeScopes(own), ...lines];
}

/** Like describeScopesWithApis, but keeps which scope each line is for, in the same order. */
export async function describeEachScope(scopes: string[], resources?: string[]): Promise<Array<{ scope: string; text: string }>> {
  const order = Object.keys(SCOPE_MEANING);
  const own = [...new Set(scopes.filter((s) => s in SCOPE_MEANING))].sort((a, b) => order.indexOf(a) - order.indexOf(b));
  const others = [...new Set(scopes.filter((s) => !(s in SCOPE_MEANING)))];
  const otherText = others.length ? (await describeScopesWithApis(others, resources)) : [];
  return [
    ...own.map((scope) => ({ scope, text: SCOPE_MEANING[scope]! })),
    ...others.map((scope, i) => ({ scope, text: otherText[i] ?? scope })),
  ];
}
