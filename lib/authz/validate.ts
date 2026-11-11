import { AppError } from "@/lib/api/errors";
import { validateConditions, type Condition } from "@/lib/authz/conditions";

/** Conditions as an API answer: a 400 with what's wrong, rather than a thrown Error. */
export function validConditions(conditions: Condition[]): Condition[] {
  if (conditions.length > 10) throw new AppError("Up to 10 conditions on an assignment", 400, "invalid_condition");
  try {
    return validateConditions(conditions.map((c) => ({ attribute: c.attribute.trim().toLowerCase(), op: c.op.trim().toLowerCase(), value: c.value.trim() })));
  } catch (error) {
    throw new AppError(error instanceof Error ? error.message : "Invalid condition", 400, "invalid_condition");
  }
}
