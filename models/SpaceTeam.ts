import { Schema, models, model, type InferSchemaType, type Model, type Types } from "mongoose";

/** A team (group) inside a space, possibly inside another team (lib/spaces/teams.ts). */
const spaceTeamSchema = new Schema(
  {
    organizationId: { type: Schema.Types.ObjectId, ref: "Organization", required: true, index: true },
    name: { type: String, required: true, trim: true },
    parentId: { type: Schema.Types.ObjectId, ref: "SpaceTeam", default: null },
    memberIds: { type: [Schema.Types.ObjectId], ref: "User", default: [], index: true },
    // SCIM (lib/scim/groups.ts): the directory group this team mirrors.
    scimExternalId: { type: String, default: null },
  },
  { timestamps: true },
);

spaceTeamSchema.index({ organizationId: 1, parentId: 1, name: 1 }, { unique: true });

export type SpaceTeamDocument = InferSchemaType<typeof spaceTeamSchema> & { _id: Types.ObjectId };

export const SpaceTeam: Model<SpaceTeamDocument> =
  (models.SpaceTeam as Model<SpaceTeamDocument>) || model<SpaceTeamDocument>("SpaceTeam", spaceTeamSchema, "space_teams");
