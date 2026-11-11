export function RenderHtml({ rawInput }) {
  return <div dangerouslySetInnerHTML={{ __html: rawInput }} />;
}
