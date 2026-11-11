import { notFound } from "next/navigation";
import { getCategory } from "@/lib/docs/registry";
import { DocsCategory } from "@/components/docs/DocsHome";

type Params = { params: Promise<{ category: string }> };

export async function generateMetadata({ params }: Params) {
  const category = getCategory((await params).category);
  return { title: category?.title ?? "Not found" };
}

export default async function DocsCategoryPage({ params }: Params) {
  const category = getCategory((await params).category);
  if (!category) notFound();
  return <DocsCategory category={category} />;
}
