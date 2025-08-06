// amplify/backend/api/<yourApi>/resolvers/KbRetrieve/request.js

/**
 * Builds the Bedrock KB /retrieve request.
 * Environment-driven parameters:
 * - KB_ID                   (e.g. “F123456789”)
 * - KB_NUM_RESULTS          (default 10)
 * - KB_OVERRIDE_SEARCH_TYPE (HYBRID or SEMANTIC; default HYBRID)
 */
export function request(ctx) {
  const { input }      = ctx.args;
  const kbId           = process.env.KB_ID;
  const numResults     = parseInt(process.env.KB_NUM_RESULTS || "10", 10);
  const overrideSearch = process.env.KB_OVERRIDE_SEARCH_TYPE || "HYBRID";

  return {
    resourcePath: `/knowledgebases/${kbId}/retrieve`,
    method:       "POST",
    params: {
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        retrievalQuery: { text: input },
        retrievalConfiguration: {
          vectorSearchConfiguration: {
            numberOfResults:    numResults,
            overrideSearchType: overrideSearch,
          },
        },
      }),
    },
  };
}
