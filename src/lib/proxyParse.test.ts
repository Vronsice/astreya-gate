import test from "node:test";
import assert from "node:assert/strict";
import {
  parseProxyInput,
  isParseReject,
  type ParsedProxy,
} from "./proxyParse.ts";

/*
  Тесты умного парсера прокси-строк: форматы шопов, схемы, неоднозначности.
*/

/** Распарсить и гарантировать успех — иначе падение с понятным сообщением. */
function expectProxy(input: string): ParsedProxy {
  const r = parseProxyInput(input);
  if (r === null || isParseReject(r)) {
    throw new Error(`ожидали успешный разбор «${input}»`);
  }
  return r;
}

test("standard URL with auth parses high", () => {
  const r = expectProxy("http://user:pass@1.2.3.4:8080");
  assert.equal(r.host, "1.2.3.4");
  assert.equal(r.port, 8080);
  assert.equal(r.username, "user");
  assert.equal(r.password, "pass");
  assert.equal(r.confidence, "high");
  assert.equal(r.url, "http://user:pass@1.2.3.4:8080");
});

test("provider format ip:port:user:pass parses high", () => {
  const r = expectProxy("212.175.16.96:40695:ALJYZGN8:D2OP70QU");
  assert.equal(r.host, "212.175.16.96");
  assert.equal(r.port, 40695);
  assert.equal(r.username, "ALJYZGN8");
  assert.equal(r.confidence, "high");
  assert.equal(r.url, "http://ALJYZGN8:D2OP70QU@212.175.16.96:40695");
});

test("reversed format user:pass:host:port resolves by IP position", () => {
  const r = expectProxy("login:secret:10.0.0.5:9000");
  assert.equal(r.host, "10.0.0.5");
  assert.equal(r.username, "login");
});

test("ambiguous format returns low confidence + alternative", () => {
  // Обе стороны выглядят как host:port и ни одна не IP → парсер честно
  // не уверен и предлагает выбор.
  const r = expectProxy("proxy.example.com:3128:other.example.com:8080");
  assert.equal(r.confidence, "low");
  assert.ok(r.alt, "ожидается альтернативная трактовка");
});

test("socks5 scheme is preserved in URL", () => {
  const r = expectProxy("socks5://u:p@5.6.7.8:1080");
  assert.match(r.url, /^socks5:\/\//);
  assert.equal(r.port, 1080);
});

test("bare host:port without auth", () => {
  const r = expectProxy("127.0.0.1:2080");
  assert.equal(r.url, "http://127.0.0.1:2080");
  assert.equal(r.username, undefined);
});

test("space-separated form joins to 4 parts", () => {
  const r = expectProxy("1.2.3.4:8080 user pass");
  assert.equal(r.username, "user");
  assert.equal(r.password, "pass");
});

test("garbage returns null or reject, never a parsed proxy", () => {
  assert.equal(parseProxyInput(""), null);
  assert.equal(parseProxyInput("   "), null);
  assert.equal(parseProxyInput("not-a-proxy"), null);
  const r = parseProxyInput("ftp://x:y@1.2.3.4:21");
  // ftp не даёт ни одной валидной трактовки → null или reject; в любом случае
  // url с схемой ftp наружу не выходит.
  if (r !== null && !isParseReject(r)) {
    assert.doesNotMatch(r.url, /^ftp:/);
  }
});
