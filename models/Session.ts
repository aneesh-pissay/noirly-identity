import { Schema, models, model, type InferSchemaType, type Model, Types } from "mongoose";

const sessionSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true },
    lastActivityAt: { type: Date, default: Date.now },
    ipAddress: { type: String, default: null },
    userAgent: { type: String, default: null },
    // Roughly where it was signed in, from the hosting edge (lib/api/request.ts).
    place: { type: String, default: null },
    revokedAt: { type: Date, default: null },
    securityVerifiedAt: { type: Date, default: null },
    // How this session was signed in (lib/auth/acr.ts gives apps amr and acr from it).
    methods: { type: [String], default: [] },
    // When the person last proved who they are in this session: its start, or a later step-up.
    authenticatedAt: { type: Date, default: null },
    // Shown the "set up a second step" nudge on the way to an app (once per session).
    mfaNudgedAt: { type: Date, default: null },
    // Apps this session has signed in to (their client ids), whether or not they still are.
    appIds: { type: [String], default: [] },
    // The account's session policy when this session started or the policy last changed (lib/sessions/lifetime.ts).
    idleTimeoutSeconds: { type: Number, default: null },
    // Never extended past this, even by mobile refreshes. Null: no account limit.
    absoluteExpiresAt: { type: Date, default: null },
    // The `sid` apps know this session by (lib/oidc/sid.ts), for the session check.
    sid: { type: String, default: null, index: { sparse: true } },
  },
  {
    timestamps: false,
  },
);

sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type SessionDocument = InferSchemaType<typeof sessionSchema> & {
  _id: Types.ObjectId;
};

export const Session: Model<SessionDocument> =
  (models.Session as Model<SessionDocument>) ||
  model<SessionDocument>("Session", sessionSchema);
