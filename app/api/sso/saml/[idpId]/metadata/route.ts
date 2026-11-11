import { NextRequest, NextResponse } from "next/server";
import { Types } from "mongoose";
import { AppError, errorResponse } from "@/lib/api/errors";
import { withDb } from "@/lib/api/with-db";
import { serviceProviderMetadata } from "@/lib/federation/sso";
import { IdentityProvider, type IdentityProviderDocument } from "@/models/IdentityProvider";

type Params = { params: Promise<{ idpId: string }> };

/** Identity's service provider metadata for one IdP connection (entity ID, ACS URL), to import at the IdP. */
export async function GET(_request: NextRequest, { params }: Params) {
  try {
    return await withDb(async () => {
      const { idpId } = await params;
      const idp = Types.ObjectId.isValid(idpId) ? await IdentityProvider.findOne({ _id: new Types.ObjectId(idpId), protocol: "saml" }).lean<IdentityProviderDocument>() : null;
      if (!idp) throw new AppError("Not found", 404, "not_found");
      return new NextResponse(serviceProviderMetadata(idp), { headers: { "content-type": "application/samlmetadata+xml; charset=utf-8", "cache-control": "public, max-age=300" } });
    });
  } catch (error) {
    return errorResponse(error);
  }
}
