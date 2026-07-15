<?php
// OpenSearch description document: lets browsers (modern ones, and a few
// surprisingly old ones) add DuckFind as a native search engine. Advertised
// via <link rel="search"> in page_head().
require __DIR__ . '/lib.php';

header('Content-Type: application/opensearchdescription+xml; charset=UTF-8');
$base = rtrim((string)df_cfg('base_url', 'http://duckfind.com'), '/');
$name = htmlspecialchars(DUCKFIND_NAME, ENT_XML1);
$tmpl = htmlspecialchars($base . '/?q={searchTerms}', ENT_XML1);
$icon = htmlspecialchars($base . '/favicon.gif', ENT_XML1);

echo '<' . '?xml version="1.0" encoding="UTF-8"?' . '>' . "\n";
echo <<<XML
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
  <ShortName>$name</ShortName>
  <Description>$name - the modern web in plain HTML, for vintage browsers</Description>
  <InputEncoding>UTF-8</InputEncoding>
  <Image height="16" width="16" type="image/gif">$icon</Image>
  <Url type="text/html" method="get" template="$tmpl"/>
</OpenSearchDescription>
XML;
