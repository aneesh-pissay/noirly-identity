import { notFound } from "next/navigation";
import { getArticle, getCategory, mediaFor } from "@/lib/docs/registry";
import { DocArticleView } from "@/components/docs/DocArticleView";

type Params = { params: Promise<{ category: string; article: string }> };

async function resolve(params: Params["params"]) {
  const { category: categoryId, article: articleId } = await params;
  const article = getArticle(articleId);
  const category = getCategory(categoryId);
  // An article answers only under its own category, so every page has one URL.
  if (!article || !category || article.category !== category.id) return null;
  return { article, category };
}

export async function generateMetadata({ params }: Params) {
  const found = await resolve(params);
  return found ? { title: found.article.title, description: found.article.summary } : { title: "Not found" };
}

export default async function DocsArticlePage({ params }: Params) {
  const found = await resolve(params);
  if (!found) notFound();
  return <DocArticleView article={found.article} category={found.category} media={mediaFor(found.article.id)} />;
}
