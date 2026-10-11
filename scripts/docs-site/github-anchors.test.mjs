import assert from "node:assert/strict";
import GithubSlugger from "github-slugger";
import MarkdownIt from "markdown-it";
import test from "node:test";
import { githubHeadingVisibleText } from "./github-anchors.mjs";

test("github heading aliases slug visible heading text", () => {
  const md = new MarkdownIt();
  const slugger = new GithubSlugger();
  const tokens = md.parse("## See [the guide](./guide.md)\n", {});
  const headingOpen = tokens.findIndex((token) => token.type === "heading_open");
  const visible = githubHeadingVisibleText(tokens[headingOpen + 1]);
  assert.equal(visible, "See the guide");
  assert.equal(slugger.slug(visible), "see-the-guide");
  assert.notEqual(slugger.slug(tokens[headingOpen + 1].content), "see-the-guide");
});
