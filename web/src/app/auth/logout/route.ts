import { NEXT_PUBLIC_CLOUD_ENABLED } from "@/lib/constants";
import { getAuthTypeMetadataSS, logoutSS } from "@/lib/userSS";
import { NextRequest } from "next/server";

export const POST = async (request: NextRequest) => {
  // Directs the logout request to the appropriate FastAPI endpoint.
  // Needed since env variables don't work well on the client-side
  const authTypeMetadata = await getAuthTypeMetadataSS();
  const response = await logoutSS(authTypeMetadata.authType, request.headers);

  if (response && !response.ok) {
    return new Response(response.body, { status: response?.status });
  }

  // Check if backend returned a redirect (for OIDC logout to Keycloak)
  if (response && (response.status === 307 || response.status === 302)) {
    console.log("Frontend logout route: Clearing cookies and redirecting to Keycloak");
    
    // Clear cookies BEFORE redirecting to Keycloak
    const cookiesToDelete = ["fastapiusersauth", "onyx_tid"];
    const cookieOptions = {
      path: "/",
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax" as const,
    };

    const headers = new Headers(response.headers); // Copy redirect headers

    cookiesToDelete.forEach((cookieName) => {
      headers.append(
        "Set-Cookie",
        `${cookieName}=; Max-Age=0; ${Object.entries(cookieOptions)
          .map(([key, value]) => `${key}=${value}`)
          .join("; ")}`
      );
    });
    
    // Return redirect with cookies cleared
    return new Response(null, {
      status: response.status,
      headers: headers
    });
  }

  // For non-redirect responses, clear cookies and return success
  const cookiesToDelete = ["fastapiusersauth", "onyx_tid"];
  const cookieOptions = {
    path: "/",
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "lax" as const,
  };

  // Logout successful, delete cookies
  const headers = new Headers();

  cookiesToDelete.forEach((cookieName) => {
    headers.append(
      "Set-Cookie",
      `${cookieName}=; Max-Age=0; ${Object.entries(cookieOptions)
        .map(([key, value]) => `${key}=${value}`)
        .join("; ")}`
    );
  });

  return new Response(null, {
    status: 204,
    headers: headers,
  });
};
