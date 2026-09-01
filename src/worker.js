const C_SERVICE = "da-storage-b2";

async function getB2Auth(env, ctx, forceRefresh = false) {
  const cache = caches.default;
  const cacheKey = new Request("https://b2-auth.internal/token", {
    method: "GET"
  });

  if (!forceRefresh) {
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      return await cachedResponse.json();
    }
  }

  const keyId = env.B2_KEY_ID;
  const appKey = env.B2_APPLICATION_KEY;

  if (!keyId || !appKey) {
    throw new Error("Missing B2_KEY_ID or B2_APPLICATION_KEY environment variables");
  }

  const authHeader = "Basic " + btoa(`${keyId}:${appKey}`);

  const authRes = await fetch(
    "https://api.backblazeb2.com/b2api/v2/b2_authorize_account",
    {
      headers: {
        Authorization: authHeader
      }
    }
  );

  const rawText = await authRes.text();

  if (!authRes.ok) {
    throw new Error(`B2 Auth failed (${authRes.status}): ${rawText}`);
  }

  const authData = JSON.parse(rawText);

  const responseToCache = new Response(JSON.stringify(authData), {
    headers: {
      "Cache-Control": "public, max-age=82800",
      "Content-Type": "application/json"
    }
  });

  ctx.waitUntil(cache.put(cacheKey, responseToCache));

  return authData;
}

async function clearB2AuthCache(ctx) {
  const cache = caches.default;
  const cacheKey = new Request("https://b2-auth.internal/", {
    method: "GET"
  });

  ctx.waitUntil(cache.delete(cacheKey));
}

export default {
  async fetch(request, env, ctx) {
    const expectedToken = env.DA_WRITE_TOKEN;

    if (expectedToken) {
      const authHeader = request.headers.get("Authorization");
      const gatewaySecret = request.headers.get("X-DA-Gateway-Secret");
      const bearerToken = authHeader?.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;

      if (
        gatewaySecret !== expectedToken &&
        bearerToken !== expectedToken
      ) {
        return rawError(
          "UNAUTHORIZED",
          "Missing or invalid authorization token",
          401
        );
      }
    }

    const service = request.headers.get("X-DA-Service");
    const action = request.headers.get("X-DA-Action");
    const fileKey = request.headers.get("X-DA-File-Key");
    const prefix = request.headers.get("X-DA-Prefix") || "";

    if (!service) {
      return rawError(
        "INVALID_SERVICE",
        "Missing X-DA-Service header",
        400
      );
    }

    if (service !== C_SERVICE) {
      return rawError(
        "INVALID_SERVICE",
        `Invalid service: ${service}`,
        400
      );
    }

    if (!action) {
      return rawError(
        "INVALID_ACTION",
        "Missing X-DA-Action header",
        400
      );
    }

    try {
      let auth = await getB2Auth(env, ctx);

      let response = await handleStorageAction(
        action,
        fileKey,
        prefix,
        request,
        env,
        auth
      );

      if (response.status === 401) {
        await clearB2AuthCache(ctx);

        auth = await getB2Auth(env, ctx, true);

        response = await handleStorageAction(
          action,
          fileKey,
          prefix,
          request,
          env,
          auth
        );
      }

      return response;
    } catch (err) {
      return rawError(
        "STORAGE_ERROR",
        err?.message || "Internal storage failure",
        500
      );
    }
  }
};

async function handleStorageAction(
  action,
  fileKey,
  prefix,
  request,
  env,
  auth
) {
  if (action === "download") {
    if (!fileKey) {
      return rawError(
        "INVALID_FIELD",
        "Missing X-DA-File-Key header",
        400
      );
    }

    const fileUrl =
      `${auth.downloadUrl}/file/${env.B2_BUCKET_NAME}/` +
      `${encodeURIComponent(fileKey)}`;

    const b2Res = await fetch(fileUrl, {
      headers: {
        Authorization: auth.authorizationToken
      }
    });

    if (b2Res.status === 401) {
      return b2Res;
    }

    if (b2Res.status === 404) {
      return rawError(
        "FILE_NOT_FOUND",
        `File key not found: ${fileKey}`,
        404
      );
    }

    if (!b2Res.ok) {
      return rawError(
        "B2_ERROR",
        `B2 Download Failed: ${b2Res.statusText}`,
        b2Res.status
      );
    }

    const headers = new Headers();

    headers.set(
      "Content-Type",
      b2Res.headers.get("Content-Type") ||
        "application/octet-stream"
    );

    const contentLength = b2Res.headers.get("Content-Length");

    if (contentLength) {
      headers.set("Content-Length", contentLength);
    }

    const fileName = fileKey.split("/").pop() || "download";

    headers.set(
      "Content-Disposition",
      `inline; filename="${fileName.replace(/"/g, '\\"')}"`
    );

    headers.set("X-DA-Service", C_SERVICE);

    return new Response(b2Res.body, {
      status: 200,
      headers
    });
  }

  if (action === "upload") {
    if (!fileKey) {
      return rawError(
        "INVALID_FIELD",
        "Missing X-DA-File-Key header",
        400
      );
    }

    if (!request.body) {
      return rawError(
        "EMPTY_BODY",
        "Upload body is empty",
        400
      );
    }

    const uploadUrlRes = await fetch(
      `${auth.apiUrl}/b2api/v3/b2_get_upload_url`,
      {
        method: "POST",
        headers: {
          Authorization: auth.authorizationToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          bucketId: env.B2_BUCKET_ID
        })
      }
    );

    if (uploadUrlRes.status === 401) {
      return uploadUrlRes;
    }

    if (!uploadUrlRes.ok) {
      return rawError(
        "B2_ERROR",
        "Failed to fetch B2 upload URL",
        502
      );
    }

    const uploadData = await uploadUrlRes.json();

    const contentType =
      request.headers.get("Content-Type") ||
      "b2/x-auto";

    const uploadHeaders = {
      Authorization: uploadData.authorizationToken,
      "X-Bz-File-Name": encodeURIComponent(fileKey),
      "Content-Type": contentType,
      "X-Bz-Content-Sha1": "do_not_verify"
    };

    const contentLength = request.headers.get("Content-Length");

    if (contentLength) {
      uploadHeaders["Content-Length"] = contentLength;
    }

    const uploadRes = await fetch(uploadData.uploadUrl, {
      method: "POST",
      headers: uploadHeaders,
      body: request.body
    });

    if (uploadRes.status === 401) {
      return uploadRes;
    }

    const resultText = await uploadRes.text();

    let resultJson;

    try {
      resultJson = JSON.parse(resultText);
    } catch {
      resultJson = {};
    }

    if (!uploadRes.ok) {
      return rawError(
        "UPLOAD_FAILED",
        resultJson.message || "Upload failed",
        uploadRes.status
      );
    }

    return rawJson({
      status: "Uploaded",
      fileId: resultJson.fileId,
      fileName: resultJson.fileName,
      size: resultJson.contentLength
    });
  }

  if (action === "list") {
    const listRes = await fetch(
      `${auth.apiUrl}/b2api/v2/b2_list_file_names`,
      {
        method: "POST",
        headers: {
          Authorization: auth.authorizationToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          bucketId: env.B2_BUCKET_ID,
          prefix,
          maxFileCount: 100
        })
      }
    );

    if (listRes.status === 401) {
      return listRes;
    }

    if (!listRes.ok) {
      return rawError(
        "B2_ERROR",
        "Failed to list files from B2",
        listRes.status
      );
    }

    const listData = await listRes.json();

    return rawJson({
      files: listData.files || [],
      nextFileName: listData.nextFileName || null
    });
  }

  if (action === "delete") {
    if (!fileKey) {
      return rawError(
        "INVALID_FIELD",
        "Missing X-DA-File-Key header",
        400
      );
    }

    const statRes = await fetch(
      `${auth.apiUrl}/b2api/v2/b2_list_file_names`,
      {
        method: "POST",
        headers: {
          Authorization: auth.authorizationToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          bucketId: env.B2_BUCKET_ID,
          prefix: fileKey,
          maxFileCount: 1
        })
      }
    );

    if (statRes.status === 401) {
      return statRes;
    }

    if (!statRes.ok) {
      return rawError(
        "B2_ERROR",
        "Failed to find file in B2",
        statRes.status
      );
    }

    const statData = await statRes.json();

    const targetFile = statData.files?.find(
      file => file.fileName === fileKey
    );

    if (!targetFile) {
      return rawError(
        "FILE_NOT_FOUND",
        `File key not found: ${fileKey}`,
        404
      );
    }

    const deleteRes = await fetch(
      `${auth.apiUrl}/b2api/v2/b2_delete_file_version`,
      {
        method: "POST",
        headers: {
          Authorization: auth.authorizationToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          fileName: targetFile.fileName,
          fileId: targetFile.fileId
        })
      }
    );

    if (deleteRes.status === 401) {
      return deleteRes;
    }

    if (!deleteRes.ok) {
      return rawError(
        "DELETE_FAILED",
        "Failed to delete file",
        deleteRes.status
      );
    }

    return rawJson({
      status: "Deleted",
      fileKey
    });
  }

  return rawError(
    "INVALID_ACTION",
    `Unsupported action: ${action}`,
    400
  );
}

function rawJson(payload, status = 200) {
  return new Response(
    JSON.stringify(payload),
    {
      status,
      headers: {
        "Content-Type": "application/json"
      }
    }
  );
}

function rawError(code, message, status = 400) {
  return new Response(
    JSON.stringify({
      status: "error",
      code,
      message
    }),
    {
      status,
      headers: {
        "Content-Type": "application/json"
      }
    }
  );
}
