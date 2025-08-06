// amplify/backend/api/<yourApi>/resolvers/KbRetrieve/response.js

/**
 * Parses the /retrieve response, surfaces errors,
 * and returns a structured payload:
 * {
 *   retrieval:  [ { id, content, metadata, confidence } ],
 *   citations:  [ { title, sourceUri, location, confidence } ]
 * }
 *
 * Here, `confidence` is the raw `chunk.score` from Bedrock
 * (cosine similarity or reranker score).
 */
export function response(ctx) {
  const { statusCode, body } = ctx.result;

  // 1) Error handling
  if (statusCode < 200 || statusCode >= 300) {
    throw new Error(`Bedrock KB retrieve failed [${statusCode}]: ${body}`);
  }

  let payload;
  try {
    payload = JSON.parse(body);
  } catch (err) {
    throw new Error(`Invalid JSON from Bedrock KB: ${err.message}`);
  }

  // 2) Map raw chunks to a retrieval array
  const retrieval = (payload.results || []).map(chunk => ({
    id:         chunk.id,
    content:    chunk.content,
    metadata:   chunk.metadata || {},
    confidence: chunk.score,              // similarity or reranker score
  }));

  // 3) Build a simple citations list from metadata + reuse confidence
  const citations = retrieval.map(item => ({
    title:      item.metadata.title      || item.metadata.source || "Unknown",
    sourceUri:  item.metadata.sourceUri  || null,
    location:   item.metadata.pageNumber != null
                  ? `page ${item.metadata.pageNumber}`
                  : item.metadata.chunkId
                    ? `chunk ${item.metadata.chunkId}`
                    : null,
    confidence: item.confidence,
  }));

  // 4) Return both for your GraphQL schema
  return { retrieval, citations };
}
