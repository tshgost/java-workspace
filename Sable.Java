import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;

public class Sable {
    public static void main(String[] args) throws Exception {
        var in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        var out = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), true);
        var err = new PrintWriter(new OutputStreamWriter(System.err, StandardCharsets.UTF_8), true);
        var sable = new SableRuntime(out, err);
        if (args.length == 0) {
            sable.repl(in);
            return;
        }
        if (args.length == 1 && args[0].equals("--demo")) {
            sable.run("<demo>", DEMO);
            return;
        }
        var path = Paths.get(args[0]);
        var src = Files.readString(path, StandardCharsets.UTF_8);
        sable.run(path.toAbsolutePath().toString(), src);
    }

    static final String DEMO = String.join("\n",
            "let fib = fn(n){ if(n <= 1){ return n; } return fib(n-1) + fib(n-2); };",
            "print(\"fib(10)=\" + fib(10));",
            "let xs = range(1, 12);",
            "let ys = map(xs, fn(x){ return x * x; });",
            "print(json_stringify(ys));",
            "let job = spawn(fn(){ let i = 0; let acc = 0; while(i < 200000){ acc = acc + (i % 97); i = i + 1; } return acc; });",
            "print(\"async=\" + await(job));",
            "let doc = json_parse(\"{\\\"a\\\":1,\\\"b\\\":[true,false,null,3.5],\\\"c\\\":\\\"ok\\\"}\");",
            "print(type(doc));",
            "print(doc[\"b\"][3]);"
    );

    static final class SableRuntime {
        private final PrintWriter out;
        private final PrintWriter err;
        private final Interpreter interpreter;

        SableRuntime(PrintWriter out, PrintWriter err) {
            this.out = out;
            this.err = err;
            this.interpreter = new Interpreter(out, err);
        }

        void repl(BufferedReader in) throws IOException {
            out.println("Sable REPL 1.0  (exit with Ctrl+D)");
            var buf = new StringBuilder();
            int depth = 0;
            boolean inStr = false;
            String prompt = "> ";
            while (true) {
                out.print(prompt);
                out.flush();
                String line = in.readLine();
                if (line == null) break;
                buf.append(line).append('\n');
                for (int i = 0; i < line.length(); i++) {
                    char c = line.charAt(i);
                    if (c == '"' && (i == 0 || line.charAt(i - 1) != '\\')) inStr = !inStr;
                    if (inStr) continue;
                    if (c == '{' || c == '(' || c == '[') depth++;
                    if (c == '}' || c == ')' || c == ']') depth--;
                }
                if (depth > 0 || inStr) {
                    prompt = "... ";
                    continue;
                }
                prompt = "> ";
                String src = buf.toString();
                buf.setLength(0);
                if (src.trim().isEmpty()) continue;
                try {
                    run("<repl>", src);
                } catch (SableError e) {
                    err.println(e.getMessage());
                } catch (RuntimeException e) {
                    err.println("runtime: " + e.getMessage());
                }
            }
        }

        void run(String name, String src) {
            var lexer = new Lexer(name, src);
            var tokens = lexer.scanTokens();
            var parser = new Parser(tokens);
            var program = parser.parse();
            interpreter.execute(program);
        }
    }

    static final class SableError extends RuntimeException {
        SableError(String msg) { super(msg); }
    }

    enum TokenType {
        LEFT_PAREN, RIGHT_PAREN, LEFT_BRACE, RIGHT_BRACE, LEFT_BRACKET, RIGHT_BRACKET,
        COMMA, DOT, SEMICOLON, COLON,
        PLUS, MINUS, STAR, SLASH, PERCENT,
        BANG, BANG_EQUAL,
        EQUAL, EQUAL_EQUAL,
        GREATER, GREATER_EQUAL,
        LESS, LESS_EQUAL,
        AND_AND, OR_OR,
        IDENT, STRING, NUMBER,
        LET, FN, IF, ELSE, WHILE, RETURN, TRUE, FALSE, NULL,
        EOF
    }

    static final class Token {
        final TokenType type;
        final String lexeme;
        final Object literal;
        final int line;
        final int col;

        Token(TokenType type, String lexeme, Object literal, int line, int col) {
            this.type = type;
            this.lexeme = lexeme;
            this.literal = literal;
            this.line = line;
            this.col = col;
        }

        public String toString() {
            return type + " " + lexeme + (literal != null ? " " + literal : "");
        }
    }

    static final class Lexer {
        private final String name;
        private final String src;
        private final int n;
        private final List<Token> tokens = new ArrayList<>();
        private int start = 0;
        private int current = 0;
        private int line = 1;
        private int col = 1;
        private int startCol = 1;

        private static final Map<String, TokenType> keywords = Map.ofEntries(
                Map.entry("let", TokenType.LET),
                Map.entry("fn", TokenType.FN),
                Map.entry("if", TokenType.IF),
                Map.entry("else", TokenType.ELSE),
                Map.entry("while", TokenType.WHILE),
                Map.entry("return", TokenType.RETURN),
                Map.entry("true", TokenType.TRUE),
                Map.entry("false", TokenType.FALSE),
                Map.entry("null", TokenType.NULL)
        );

        Lexer(String name, String src) {
            this.name = name;
            this.src = src;
            this.n = src.length();
        }

        List<Token> scanTokens() {
            while (!isAtEnd()) {
                start = current;
                startCol = col;
                scanToken();
            }
            tokens.add(new Token(TokenType.EOF, "", null, line, col));
            return tokens;
        }

        private boolean isAtEnd() { return current >= n; }

        private char advance() {
            char c = src.charAt(current++);
            if (c == '\n') { line++; col = 1; } else { col++; }
            return c;
        }

        private boolean match(char expected) {
            if (isAtEnd()) return false;
            if (src.charAt(current) != expected) return false;
            current++;
            col++;
            return true;
        }

        private char peek() { return isAtEnd() ? '\0' : src.charAt(current); }

        private char peekNext() { return current + 1 >= n ? '\0' : src.charAt(current + 1); }

        private void add(TokenType type) { add(type, null); }

        private void add(TokenType type, Object lit) {
            String text = src.substring(start, current);
            tokens.add(new Token(type, text, lit, line, startCol));
        }

        private void scanToken() {
            char c = advance();
            switch (c) {
                case '(': add(TokenType.LEFT_PAREN); break;
                case ')': add(TokenType.RIGHT_PAREN); break;
                case '{': add(TokenType.LEFT_BRACE); break;
                case '}': add(TokenType.RIGHT_BRACE); break;
                case '[': add(TokenType.LEFT_BRACKET); break;
                case ']': add(TokenType.RIGHT_BRACKET); break;
                case ',': add(TokenType.COMMA); break;
                case '.': add(TokenType.DOT); break;
                case ';': add(TokenType.SEMICOLON); break;
                case ':': add(TokenType.COLON); break;
                case '+': add(TokenType.PLUS); break;
                case '-': add(TokenType.MINUS); break;
                case '*': add(TokenType.STAR); break;
                case '%': add(TokenType.PERCENT); break;
                case '!': add(match('=') ? TokenType.BANG_EQUAL : TokenType.BANG); break;
                case '=': add(match('=') ? TokenType.EQUAL_EQUAL : TokenType.EQUAL); break;
                case '<': add(match('=') ? TokenType.LESS_EQUAL : TokenType.LESS); break;
                case '>': add(match('=') ? TokenType.GREATER_EQUAL : TokenType.GREATER); break;
                case '&':
                    if (match('&')) add(TokenType.AND_AND); else error("unexpected '&'");
                    break;
                case '|':
                    if (match('|')) add(TokenType.OR_OR); else error("unexpected '|'");
                    break;
                case '/':
                    if (match('/')) {
                        while (peek() != '\n' && !isAtEnd()) advance();
                    } else if (match('*')) {
                        while (!isAtEnd()) {
                            if (peek() == '*' && peekNext() == '/') { advance(); advance(); break; }
                            advance();
                        }
                    } else {
                        add(TokenType.SLASH);
                    }
                    break;
                case ' ':
                case '\r':
                case '\t':
                case '\n':
                    break;
                case '"': string(); break;
                default:
                    if (isDigit(c)) number();
                    else if (isAlpha(c)) identifier();
                    else error("unexpected character: " + c);
            }
        }

        private void string() {
            var sb = new StringBuilder();
            while (!isAtEnd() && peek() != '"') {
                char c = advance();
                if (c == '\\') {
                    if (isAtEnd()) error("unterminated string");
                    char e = advance();
                    switch (e) {
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case 'u':
                            String hex = "" + advance() + advance() + advance() + advance();
                            sb.append((char) Integer.parseInt(hex, 16));
                            break;
                        default: sb.append(e);
                    }
                } else {
                    sb.append(c);
                }
            }
            if (isAtEnd()) error("unterminated string");
            advance();
            add(TokenType.STRING, sb.toString());
        }

        private void number() {
            while (isDigit(peek())) advance();
            if (peek() == '.' && isDigit(peekNext())) {
                advance();
                while (isDigit(peek())) advance();
            }
            String text = src.substring(start, current);
            try {
                add(TokenType.NUMBER, Double.parseDouble(text));
            } catch (NumberFormatException e) {
                error("invalid number: " + text);
            }
        }

        private void identifier() {
            while (isAlphaNumeric(peek())) advance();
            String text = src.substring(start, current);
            TokenType type = keywords.get(text);
            if (type == null) type = TokenType.IDENT;
            add(type);
        }

        private boolean isDigit(char c) { return c >= '0' && c <= '9'; }
        private boolean isAlpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
        private boolean isAlphaNumeric(char c) { return isAlpha(c) || isDigit(c); }

        private void error(String msg) {
            throw new SableError(name + ":" + line + ":" + startCol + ": " + msg);
        }
    }

    interface Expr {
        <R> R accept(ExprVisitor<R> v);
    }

    interface ExprVisitor<R> {
        R visitLiteral(Literal e);
        R visitVar(Var e);
        R visitAssign(Assign e);
        R visitUnary(Unary e);
        R visitBinary(Binary e);
        R visitCall(Call e);
        R visitLambda(Lambda e);
        R visitList(ListLit e);
        R visitIndex(Index e);
    }

    static final class Literal implements Expr {
        final Object value;
        Literal(Object value) { this.value = value; }
        public <R> R accept(ExprVisitor<R> v) { return v.visitLiteral(this); }
    }

    static final class Var implements Expr {
        final Token name;
        Var(Token name) { this.name = name; }
        public <R> R accept(ExprVisitor<R> v) { return v.visitVar(this); }
    }

    static final class Assign implements Expr {
        final Token name;
        final Expr value;
        Assign(Token name, Expr value) { this.name = name; this.value = value; }
        public <R> R accept(ExprVisitor<R> v) { return v.visitAssign(this); }
    }

    static final class Unary implements Expr {
        final Token op;
        final Expr right;
        Unary(Token op, Expr right) { this.op = op; this.right = right; }
        public <R> R accept(ExprVisitor<R> v) { return v.visitUnary(this); }
    }

    static final class Binary implements Expr {
        final Expr left;
        final Token op;
        final Expr right;
        Binary(Expr left, Token op, Expr right) { this.left = left; this.op = op; this.right = right; }
        public <R> R accept(ExprVisitor<R> v) { return v.visitBinary(this); }
    }

    static final class Call implements Expr {
        final Expr callee;
        final Token paren;
        final List<Expr> args;
        Call(Expr callee, Token paren, List<Expr> args) { this.callee = callee; this.paren = paren; this.args = args; }
        public <R> R accept(ExprVisitor<R> v) { return v.visitCall(this); }
    }

    static final class Lambda implements Expr {
        final List<Token> params;
        final List<Stmt> body;
        final Token start;
        Lambda(Token start, List<Token> params, List<Stmt> body) { this.start = start; this.params = params; this.body = body; }
        public <R> R accept(ExprVisitor<R> v) { return v.visitLambda(this); }
    }

    static final class ListLit implements Expr {
        final List<Expr> elems;
        ListLit(List<Expr> elems) { this.elems = elems; }
        public <R> R accept(ExprVisitor<R> v) { return v.visitList(this); }
    }

    static final class Index implements Expr {
        final Expr target;
        final Expr index;
        final Token bracket;
        Index(Expr target, Token bracket, Expr index) { this.target = target; this.bracket = bracket; this.index = index; }
        public <R> R accept(ExprVisitor<R> v) { return v.visitIndex(this); }
    }

    interface Stmt {
        void accept(StmtVisitor v);
    }

    interface StmtVisitor {
        void visitExprStmt(ExprStmt s);
        void visitVarDecl(VarDecl s);
        void visitBlock(Block s);
        void visitIf(If s);
        void visitWhile(While s);
        void visitReturn(Return s);
        void visitFnDecl(FnDecl s);
    }

    static final class ExprStmt implements Stmt {
        final Expr expr;
        ExprStmt(Expr expr) { this.expr = expr; }
        public void accept(StmtVisitor v) { v.visitExprStmt(this); }
    }

    static final class VarDecl implements Stmt {
        final Token name;
        final Expr init;
        VarDecl(Token name, Expr init) { this.name = name; this.init = init; }
        public void accept(StmtVisitor v) { v.visitVarDecl(this); }
    }

    static final class Block implements Stmt {
        final List<Stmt> stmts;
        Block(List<Stmt> stmts) { this.stmts = stmts; }
        public void accept(StmtVisitor v) { v.visitBlock(this); }
    }

    static final class If implements Stmt {
        final Expr cond;
        final Stmt thenBranch;
        final Stmt elseBranch;
        If(Expr cond, Stmt thenBranch, Stmt elseBranch) { this.cond = cond; this.thenBranch = thenBranch; this.elseBranch = elseBranch; }
        public void accept(StmtVisitor v) { v.visitIf(this); }
    }

    static final class While implements Stmt {
        final Expr cond;
        final Stmt body;
        While(Expr cond, Stmt body) { this.cond = cond; this.body = body; }
        public void accept(StmtVisitor v) { v.visitWhile(this); }
    }

    static final class Return implements Stmt {
        final Token kw;
        final Expr value;
        Return(Token kw, Expr value) { this.kw = kw; this.value = value; }
        public void accept(StmtVisitor v) { v.visitReturn(this); }
    }

    static final class FnDecl implements Stmt {
        final Token name;
        final List<Token> params;
        final List<Stmt> body;
        FnDecl(Token name, List<Token> params, List<Stmt> body) { this.name = name; this.params = params; this.body = body; }
        public void accept(StmtVisitor v) { v.visitFnDecl(this); }
    }

    static final class Parser {
        private final List<Token> tokens;
        private int current = 0;

        Parser(List<Token> tokens) { this.tokens = tokens; }

        List<Stmt> parse() {
            List<Stmt> stmts = new ArrayList<>();
            while (!isAtEnd()) stmts.add(declaration());
            return stmts;
        }

        private Stmt declaration() {
            if (match(TokenType.FN)) return fnDecl();
            if (match(TokenType.LET)) return varDecl();
            return statement();
        }

        private Stmt fnDecl() {
            Token name = consume(TokenType.IDENT, "expected function name");
            consume(TokenType.LEFT_PAREN, "expected '('");
            List<Token> params = new ArrayList<>();
            if (!check(TokenType.RIGHT_PAREN)) {
                do {
                    params.add(consume(TokenType.IDENT, "expected parameter name"));
                } while (match(TokenType.COMMA));
            }
            consume(TokenType.RIGHT_PAREN, "expected ')'");
            List<Stmt> body = blockBody();
            return new FnDecl(name, params, body);
        }

        private Stmt varDecl() {
            Token name = consume(TokenType.IDENT, "expected variable name");
            Expr init = null;
            if (match(TokenType.EQUAL)) init = expression();
            consume(TokenType.SEMICOLON, "expected ';'");
            return new VarDecl(name, init);
        }

        private Stmt statement() {
            if (match(TokenType.IF)) return ifStmt();
            if (match(TokenType.WHILE)) return whileStmt();
            if (match(TokenType.RETURN)) return returnStmt();
            if (match(TokenType.LEFT_BRACE)) return new Block(block());
            return exprStmt();
        }

        private Stmt ifStmt() {
            consume(TokenType.LEFT_PAREN, "expected '('");
            Expr cond = expression();
            consume(TokenType.RIGHT_PAREN, "expected ')'");
            Stmt thenBranch = statement();
            Stmt elseBranch = null;
            if (match(TokenType.ELSE)) elseBranch = statement();
            return new If(cond, thenBranch, elseBranch);
        }

        private Stmt whileStmt() {
            consume(TokenType.LEFT_PAREN, "expected '('");
            Expr cond = expression();
            consume(TokenType.RIGHT_PAREN, "expected ')'");
            Stmt body = statement();
            return new While(cond, body);
        }

        private Stmt returnStmt() {
            Token kw = previous();
            Expr v = null;
            if (!check(TokenType.SEMICOLON)) v = expression();
            consume(TokenType.SEMICOLON, "expected ';'");
            return new Return(kw, v);
        }

        private Stmt exprStmt() {
            Expr e = expression();
            consume(TokenType.SEMICOLON, "expected ';'");
            return new ExprStmt(e);
        }

        private List<Stmt> blockBody() {
            consume(TokenType.LEFT_BRACE, "expected '{'");
            return block();
        }

        private List<Stmt> block() {
            List<Stmt> stmts = new ArrayList<>();
            while (!check(TokenType.RIGHT_BRACE) && !isAtEnd()) {
                stmts.add(declaration());
            }
            consume(TokenType.RIGHT_BRACE, "expected '}'");
            return stmts;
        }

        private Expr expression() { return assignment(); }

        private Expr assignment() {
            Expr expr = or();
            if (match(TokenType.EQUAL)) {
                Token eq = previous();
                Expr value = assignment();
                if (expr instanceof Var v) return new Assign(v.name, value);
                error(eq, "invalid assignment target");
            }
            return expr;
        }

        private Expr or() {
            Expr expr = and();
            while (match(TokenType.OR_OR)) {
                Token op = previous();
                Expr right = and();
                expr = new Binary(expr, op, right);
            }
            return expr;
        }

        private Expr and() {
            Expr expr = equality();
            while (match(TokenType.AND_AND)) {
                Token op = previous();
                Expr right = equality();
                expr = new Binary(expr, op, right);
            }
            return expr;
        }

        private Expr equality() {
            Expr expr = comparison();
            while (match(TokenType.EQUAL_EQUAL, TokenType.BANG_EQUAL)) {
                Token op = previous();
                Expr right = comparison();
                expr = new Binary(expr, op, right);
            }
            return expr;
        }

        private Expr comparison() {
            Expr expr = term();
            while (match(TokenType.GREATER, TokenType.GREATER_EQUAL, TokenType.LESS, TokenType.LESS_EQUAL)) {
                Token op = previous();
                Expr right = term();
                expr = new Binary(expr, op, right);
            }
            return expr;
        }

        private Expr term() {
            Expr expr = factor();
            while (match(TokenType.PLUS, TokenType.MINUS)) {
                Token op = previous();
                Expr right = factor();
                expr = new Binary(expr, op, right);
            }
            return expr;
        }

        private Expr factor() {
            Expr expr = unary();
            while (match(TokenType.STAR, TokenType.SLASH, TokenType.PERCENT)) {
                Token op = previous();
                Expr right = unary();
                expr = new Binary(expr, op, right);
            }
            return expr;
        }

        private Expr unary() {
            if (match(TokenType.BANG, TokenType.MINUS)) {
                Token op = previous();
                Expr right = unary();
                return new Unary(op, right);
            }
            return call();
        }

        private Expr call() {
            Expr expr = primary();
            while (true) {
                if (match(TokenType.LEFT_PAREN)) {
                    Token paren = previous();
                    List<Expr> args = new ArrayList<>();
                    if (!check(TokenType.RIGHT_PAREN)) {
                        do {
                            args.add(expression());
                        } while (match(TokenType.COMMA));
                    }
                    consume(TokenType.RIGHT_PAREN, "expected ')'");
                    expr = new Call(expr, paren, args);
                } else if (match(TokenType.LEFT_BRACKET)) {
                    Token br = previous();
                    Expr idx = expression();
                    consume(TokenType.RIGHT_BRACKET, "expected ']'");
                    expr = new Index(expr, br, idx);
                } else {
                    break;
                }
            }
            return expr;
        }

        private Expr primary() {
            if (match(TokenType.FALSE)) return new Literal(false);
            if (match(TokenType.TRUE)) return new Literal(true);
            if (match(TokenType.NULL)) return new Literal(null);
            if (match(TokenType.NUMBER)) return new Literal(previous().literal);
            if (match(TokenType.STRING)) return new Literal(previous().literal);
            if (match(TokenType.IDENT)) return new Var(previous());
            if (match(TokenType.LEFT_PAREN)) {
                Expr e = expression();
                consume(TokenType.RIGHT_PAREN, "expected ')'");
                return e;
            }
            if (match(TokenType.LEFT_BRACKET)) {
                List<Expr> elems = new ArrayList<>();
                if (!check(TokenType.RIGHT_BRACKET)) {
                    do {
                        elems.add(expression());
                    } while (match(TokenType.COMMA));
                }
                consume(TokenType.RIGHT_BRACKET, "expected ']'");
                return new ListLit(elems);
            }
            if (match(TokenType.FN)) {
                Token start = previous();
                consume(TokenType.LEFT_PAREN, "expected '('");
                List<Token> params = new ArrayList<>();
                if (!check(TokenType.RIGHT_PAREN)) {
                    do {
                        params.add(consume(TokenType.IDENT, "expected parameter name"));
                    } while (match(TokenType.COMMA));
                }
                consume(TokenType.RIGHT_PAREN, "expected ')'");
                List<Stmt> body = blockBody();
                return new Lambda(start, params, body);
            }
            throw error(peek(), "expected expression");
        }

        private boolean match(TokenType... types) {
            for (TokenType t : types) {
                if (check(t)) { advance(); return true; }
            }
            return false;
        }

        private Token consume(TokenType type, String msg) {
            if (check(type)) return advance();
            throw error(peek(), msg);
        }

        private boolean check(TokenType type) {
            if (isAtEnd()) return false;
            return peek().type == type;
        }

        private Token advance() {
            if (!isAtEnd()) current++;
            return previous();
        }

        private boolean isAtEnd() { return peek().type == TokenType.EOF; }

        private Token peek() { return tokens.get(current); }

        private Token previous() { return tokens.get(current - 1); }

        private SableError error(Token t, String msg) {
            return new SableError("parse:" + t.line + ":" + t.col + ": " + msg);
        }
    }

    interface Val {
        String type();
    }

    static final class Num implements Val {
        final double v;
        Num(double v) { this.v = v; }
        public String type() { return "number"; }
    }

    static final class Str implements Val {
        final String v;
        Str(String v) { this.v = v; }
        public String type() { return "string"; }
    }

    static final class Bool implements Val {
        final boolean v;
        Bool(boolean v) { this.v = v; }
        public String type() { return "bool"; }
    }

    static final class NullVal implements Val {
        static final NullVal INSTANCE = new NullVal();
        private NullVal() {}
        public String type() { return "null"; }
    }

    static final class ListVal implements Val {
        final ArrayList<Val> v;
        ListVal(ArrayList<Val> v) { this.v = v; }
        public String type() { return "list"; }
    }

    static final class MapVal implements Val {
        final LinkedHashMap<String, Val> v;
        MapVal(LinkedHashMap<String, Val> v) { this.v = v; }
        public String type() { return "map"; }
    }

    interface Callable extends Val {
        Val call(Interpreter it, List<Val> args);
        int arityMin();
        int arityMax();
    }

    static final class NativeFn implements Callable {
        final String name;
        final int min;
        final int max;
        final NativeBody body;

        interface NativeBody { Val run(Interpreter it, List<Val> args); }

        NativeFn(String name, int min, int max, NativeBody body) {
            this.name = name;
            this.min = min;
            this.max = max;
            this.body = body;
        }

        public String type() { return "native_fn"; }
        public int arityMin() { return min; }
        public int arityMax() { return max; }
        public Val call(Interpreter it, List<Val> args) { return body.run(it, args); }
        public String toString() { return "<native " + name + ">"; }
    }

    static final class UserFn implements Callable {
        final String name;
        final List<String> params;
        final List<Stmt> body;
        final Env closure;

        UserFn(String name, List<String> params, List<Stmt> body, Env closure) {
            this.name = name;
            this.params = params;
            this.body = body;
            this.closure = closure;
        }

        public String type() { return "fn"; }
        public int arityMin() { return params.size(); }
        public int arityMax() { return params.size(); }
        public Val call(Interpreter it, List<Val> args) {
            var env = new Env(closure);
            for (int i = 0; i < params.size(); i++) env.define(params.get(i), args.get(i));
            try {
                it.executeBlock(body, env);
            } catch (ReturnSignal r) {
                return r.value;
            }
            return NullVal.INSTANCE;
        }

        public String toString() { return "<fn " + name + ">"; }
    }

    static final class FutureVal implements Val {
        final CompletableFuture<Val> f;
        FutureVal(CompletableFuture<Val> f) { this.f = f; }
        public String type() { return "future"; }
    }

    static final class Env {
        final Env parent;
        final HashMap<String, Val> values = new HashMap<>();

        Env(Env parent) { this.parent = parent; }

        void define(String name, Val v) { values.put(name, v); }

        Val get(Token name) {
            if (values.containsKey(name.lexeme)) return values.get(name.lexeme);
            if (parent != null) return parent.get(name);
            throw new SableError("runtime:" + name.line + ":" + name.col + ": undefined variable '" + name.lexeme + "'");
        }

        void assign(Token name, Val v) {
            if (values.containsKey(name.lexeme)) { values.put(name.lexeme, v); return; }
            if (parent != null) { parent.assign(name, v); return; }
            throw new SableError("runtime:" + name.line + ":" + name.col + ": undefined variable '" + name.lexeme + "'");
        }
    }

    static final class ReturnSignal extends RuntimeException {
        final Val value;
        ReturnSignal(Val value) { this.value = value; }
    }

    static final class Interpreter implements ExprVisitor<Val>, StmtVisitor {
        private final PrintWriter out;
        private final PrintWriter err;
        private Env globals;
        private Env env;
        private final ExecutorService pool;
        private final HttpClient http;

        Interpreter(PrintWriter out, PrintWriter err) {
            this.out = out;
            this.err = err;
            this.globals = new Env(null);
            this.env = globals;
            this.pool = Executors.newWorkStealingPool();
            this.http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
            installBuiltins();
        }

        void execute(List<Stmt> program) {
            for (Stmt s : program) s.accept(this);
        }

        void executeBlock(List<Stmt> stmts, Env newEnv) {
            Env prev = this.env;
            try {
                this.env = newEnv;
                for (Stmt s : stmts) s.accept(this);
            } finally {
                this.env = prev;
            }
        }

        private void installBuiltins() {
            define("print", new NativeFn("print", 0, Integer.MAX_VALUE, (it, args) -> {
                for (int i = 0; i < args.size(); i++) {
                    if (i > 0) out.print(" ");
                    out.print(stringify(args.get(i)));
                }
                out.println();
                return NullVal.INSTANCE;
            }));

            define("len", new NativeFn("len", 1, 1, (it, args) -> {
                Val v = args.get(0);
                if (v instanceof Str s) return new Num(s.v.length());
                if (v instanceof ListVal l) return new Num(l.v.size());
                if (v instanceof MapVal m) return new Num(m.v.size());
                throw new SableError("runtime: len() expects string/list/map");
            }));

            define("type", new NativeFn("type", 1, 1, (it, args) -> new Str(args.get(0).type())));

            define("clock_ms", new NativeFn("clock_ms", 0, 0, (it, args) -> new Num(System.currentTimeMillis())));

            define("sleep", new NativeFn("sleep", 1, 1, (it, args) -> {
                long ms = asLong(args.get(0));
                try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                return NullVal.INSTANCE;
            }));

            define("read", new NativeFn("read", 1, 1, (it, args) -> {
                String p = asString(args.get(0));
                try {
                    return new Str(Files.readString(Paths.get(p), StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new SableError("runtime: read failed: " + e.getMessage());
                }
            }));

            define("write", new NativeFn("write", 2, 2, (it, args) -> {
                String p = asString(args.get(0));
                String s = asString(args.get(1));
                try {
                    Files.writeString(Paths.get(p), s, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                    return NullVal.INSTANCE;
                } catch (IOException e) {
                    throw new SableError("runtime: write failed: " + e.getMessage());
                }
            }));

            define("append", new NativeFn("append", 2, 2, (it, args) -> {
                String p = asString(args.get(0));
                String s = asString(args.get(1));
                try {
                    Files.writeString(Paths.get(p), s, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                    return NullVal.INSTANCE;
                } catch (IOException e) {
                    throw new SableError("runtime: append failed: " + e.getMessage());
                }
            }));

            define("range", new NativeFn("range", 1, 3, (it, args) -> {
                long a, b, step;
                if (args.size() == 1) { a = 0; b = asLong(args.get(0)); step = 1; }
                else if (args.size() == 2) { a = asLong(args.get(0)); b = asLong(args.get(1)); step = 1; }
                else { a = asLong(args.get(0)); b = asLong(args.get(1)); step = asLong(args.get(2)); }
                if (step == 0) throw new SableError("runtime: range step cannot be 0");
                var list = new ArrayList<Val>();
                if (step > 0) {
                    for (long i = a; i < b; i += step) list.add(new Num(i));
                } else {
                    for (long i = a; i > b; i += step) list.add(new Num(i));
                }
                return new ListVal(list);
            }));

            define("map", new NativeFn("map", 2, 2, (it, args) -> {
                var list = asList(args.get(0));
                var fn = asCallable(args.get(1));
                var outList = new ArrayList<Val>(list.size());
                for (Val v : list) outList.add(fn.call(this, List.of(v)));
                return new ListVal(outList);
            }));

            define("filter", new NativeFn("filter", 2, 2, (it, args) -> {
                var list = asList(args.get(0));
                var fn = asCallable(args.get(1));
                var outList = new ArrayList<Val>();
                for (Val v : list) if (truthy(fn.call(this, List.of(v)))) outList.add(v);
                return new ListVal(outList);
            }));

            define("reduce", new NativeFn("reduce", 3, 3, (it, args) -> {
                var list = asList(args.get(0));
                Val acc = args.get(1);
                var fn = asCallable(args.get(2));
                for (Val v : list) acc = fn.call(this, List.of(acc, v));
                return acc;
            }));

            define("spawn", new NativeFn("spawn", 1, Integer.MAX_VALUE, (it, args) -> {
                var fn = asCallable(args.get(0));
                var rest = args.subList(1, args.size());
                var fut = CompletableFuture.supplyAsync(() -> fn.call(this, rest), pool);
                return new FutureVal(fut);
            }));

            define("await", new NativeFn("await", 1, 1, (it, args) -> {
                if (!(args.get(0) instanceof FutureVal f)) throw new SableError("runtime: await() expects future");
                try {
                    return f.f.get();
                } catch (ExecutionException e) {
                    throw new SableError("runtime: await failed: " + e.getCause());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new SableError("runtime: await interrupted");
                }
            }));

            define("http_get", new NativeFn("http_get", 1, 1, (it, args) -> {
                String url = asString(args.get(0));
                try {
                    var req = HttpRequest.newBuilder(URI.create(url)).GET().timeout(Duration.ofSeconds(20)).build();
                    var res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                    return new Str(res.body());
                } catch (Exception e) {
                    throw new SableError("runtime: http_get failed: " + e.getMessage());
                }
            }));

            define("json_parse", new NativeFn("json_parse", 1, 1, (it, args) -> {
                String s = asString(args.get(0));
                return Json.parse(s);
            }));

            define("json_stringify", new NativeFn("json_stringify", 1, 1, (it, args) -> new Str(Json.stringify(args.get(0)))));

            define("now_iso", new NativeFn("now_iso", 0, 0, (it, args) -> new Str(Instant.now().toString())));

            define("assert", new NativeFn("assert", 1, 2, (it, args) -> {
                if (!truthy(args.get(0))) {
                    String m = args.size() == 2 ? asString(args.get(1)) : "assertion failed";
                    throw new SableError("runtime: " + m);
                }
                return NullVal.INSTANCE;
            }));
        }

        private void define(String name, Val v) { globals.define(name, v); }

        public void visitExprStmt(ExprStmt s) { evaluate(s.expr); }

        public void visitVarDecl(VarDecl s) {
            Val v = NullVal.INSTANCE;
            if (s.init != null) v = evaluate(s.init);
            env.define(s.name.lexeme, v);
        }

        public void visitBlock(Block s) { executeBlock(s.stmts, new Env(env)); }

        public void visitIf(If s) {
            if (truthy(evaluate(s.cond))) s.thenBranch.accept(this);
            else if (s.elseBranch != null) s.elseBranch.accept(this);
        }

        public void visitWhile(While s) {
            while (truthy(evaluate(s.cond))) s.body.accept(this);
        }

        public void visitReturn(Return s) {
            Val v = NullVal.INSTANCE;
            if (s.value != null) v = evaluate(s.value);
            throw new ReturnSignal(v);
        }

        public void visitFnDecl(FnDecl s) {
            var params = new ArrayList<String>();
            for (Token t : s.params) params.add(t.lexeme);
            var fn = new UserFn(s.name.lexeme, params, s.body, env);
            env.define(s.name.lexeme, fn);
        }

        private Val evaluate(Expr e) { return e.accept(this); }

        public Val visitLiteral(Literal e) {
            if (e.value == null) return NullVal.INSTANCE;
            if (e.value instanceof Boolean b) return new Bool(b);
            if (e.value instanceof Double d) return new Num(d);
            if (e.value instanceof String s) return new Str(s);
            throw new SableError("runtime: invalid literal");
        }

        public Val visitVar(Var e) { return env.get(e.name); }

        public Val visitAssign(Assign e) {
            Val v = evaluate(e.value);
            env.assign(e.name, v);
            return v;
        }

        public Val visitUnary(Unary e) {
            Val r = evaluate(e.right);
            switch (e.op.type) {
                case BANG: return new Bool(!truthy(r));
                case MINUS: return new Num(-asNum(r));
                default: throw new SableError("runtime: invalid unary op");
            }
        }

        public Val visitBinary(Binary e) {
            if (e.op.type == TokenType.OR_OR) {
                Val left = evaluate(e.left);
                if (truthy(left)) return left;
                return evaluate(e.right);
            }
            if (e.op.type == TokenType.AND_AND) {
                Val left = evaluate(e.left);
                if (!truthy(left)) return left;
                return evaluate(e.right);
            }

            Val l = evaluate(e.left);
            Val r = evaluate(e.right);

            switch (e.op.type) {
                case PLUS:
                    if (l instanceof Str || r instanceof Str) return new Str(stringify(l) + stringify(r));
                    return new Num(asNum(l) + asNum(r));
                case MINUS: return new Num(asNum(l) - asNum(r));
                case STAR:
                    if (l instanceof Str s && r instanceof Num n) return new Str(s.v.repeat((int) clampInt(n.v)));
                    if (r instanceof Str s2 && l instanceof Num n2) return new Str(s2.v.repeat((int) clampInt(n2.v)));
                    return new Num(asNum(l) * asNum(r));
                case SLASH: return new Num(asNum(l) / asNum(r));
                case PERCENT: return new Num(asNum(l) % asNum(r));
                case GREATER: return new Bool(compare(l, r) > 0);
                case GREATER_EQUAL: return new Bool(compare(l, r) >= 0);
                case LESS: return new Bool(compare(l, r) < 0);
                case LESS_EQUAL: return new Bool(compare(l, r) <= 0);
                case EQUAL_EQUAL: return new Bool(deepEquals(l, r));
                case BANG_EQUAL: return new Bool(!deepEquals(l, r));
                default:
                    throw new SableError("runtime: invalid binary op");
            }
        }

        private long clampInt(double v) {
            if (Double.isNaN(v) || Double.isInfinite(v)) return 0;
            long x = (long) v;
            if (x < 0) return 0;
            if (x > 100000) return 100000;
            return x;
        }

        public Val visitCall(Call e) {
            Val callee = evaluate(e.callee);
            if (!(callee instanceof Callable fn)) throw new SableError("runtime:" + e.paren.line + ":" + e.paren.col + ": not callable");
            List<Val> args = new ArrayList<>();
            for (Expr a : e.args) args.add(evaluate(a));
            if (args.size() < fn.arityMin() || args.size() > fn.arityMax()) {
                throw new SableError("runtime:" + e.paren.line + ":" + e.paren.col + ": wrong arity for call");
            }
            return fn.call(this, args);
        }

        public Val visitLambda(Lambda e) {
            var params = new ArrayList<String>();
            for (Token t : e.params) params.add(t.lexeme);
            return new UserFn("<lambda@" + e.start.line + ":" + e.start.col + ">", params, e.body, env);
        }

        public Val visitList(ListLit e) {
            var list = new ArrayList<Val>();
            for (Expr ex : e.elems) list.add(evaluate(ex));
            return new ListVal(list);
        }

        public Val visitIndex(Index e) {
            Val t = evaluate(e.target);
            Val idx = evaluate(e.index);
            if (t instanceof ListVal l) {
                int i = (int) asLong(idx);
                int size = l.v.size();
                if (i < 0) i = size + i;
                if (i < 0 || i >= size) return NullVal.INSTANCE;
                return l.v.get(i);
            }
            if (t instanceof Str s) {
                int i = (int) asLong(idx);
                int size = s.v.length();
                if (i < 0) i = size + i;
                if (i < 0 || i >= size) return NullVal.INSTANCE;
                return new Str(String.valueOf(s.v.charAt(i)));
            }
            if (t instanceof MapVal m) {
                String k = asString(idx);
                return m.v.getOrDefault(k, NullVal.INSTANCE);
            }
            throw new SableError("runtime:" + e.bracket.line + ":" + e.bracket.col + ": not indexable");
        }

        private static boolean truthy(Val v) {
            if (v == NullVal.INSTANCE) return false;
            if (v instanceof Bool b) return b.v;
            return true;
        }

        private static double asNum(Val v) {
            if (v instanceof Num n) return n.v;
            throw new SableError("runtime: expected number");
        }

        private static long asLong(Val v) {
            if (v instanceof Num n) return (long) n.v;
            if (v instanceof Str s) {
                try { return Long.parseLong(s.v.trim()); } catch (Exception e) { throw new SableError("runtime: expected integer"); }
            }
            throw new SableError("runtime: expected integer");
        }

        private static String asString(Val v) {
            if (v instanceof Str s) return s.v;
            if (v instanceof Num n) {
                if (n.v == (long) n.v) return Long.toString((long) n.v);
                return Double.toString(n.v);
            }
            if (v instanceof Bool b) return b.v ? "true" : "false";
            if (v == NullVal.INSTANCE) return "null";
            return v.toString();
        }

        private static ArrayList<Val> asList(Val v) {
            if (v instanceof ListVal l) return l.v;
            throw new SableError("runtime: expected list");
        }

        private static Callable asCallable(Val v) {
            if (v instanceof Callable c) return c;
            throw new SableError("runtime: expected function");
        }

        private static int compare(Val a, Val b) {
            if (a instanceof Num x && b instanceof Num y) return Double.compare(x.v, y.v);
            if (a instanceof Str x && b instanceof Str y) return x.v.compareTo(y.v);
            throw new SableError("runtime: cannot compare");
        }

        private static boolean deepEquals(Val a, Val b) {
            if (a == b) return true;
            if (a instanceof Num x && b instanceof Num y) return Double.doubleToLongBits(x.v) == Double.doubleToLongBits(y.v);
            if (a instanceof Str x && b instanceof Str y) return Objects.equals(x.v, y.v);
            if (a instanceof Bool x && b instanceof Bool y) return x.v == y.v;
            if (a == NullVal.INSTANCE && b == NullVal.INSTANCE) return true;
            if (a instanceof ListVal x && b instanceof ListVal y) {
                if (x.v.size() != y.v.size()) return false;
                for (int i = 0; i < x.v.size(); i++) if (!deepEquals(x.v.get(i), y.v.get(i))) return false;
                return true;
            }
            if (a instanceof MapVal x && b instanceof MapVal y) {
                if (x.v.size() != y.v.size()) return false;
                for (var e : x.v.entrySet()) {
                    if (!y.v.containsKey(e.getKey())) return false;
                    if (!deepEquals(e.getValue(), y.v.get(e.getKey()))) return false;
                }
                return true;
            }
            return false;
        }

        private static String stringify(Val v) {
            if (v == NullVal.INSTANCE) return "null";
            if (v instanceof Num n) {
                if (n.v == (long) n.v) return Long.toString((long) n.v);
                String s = Double.toString(n.v);
                if (s.endsWith(".0")) s = s.substring(0, s.length() - 2);
                return s;
            }
            if (v instanceof Str s) return s.v;
            if (v instanceof Bool b) return b.v ? "true" : "false";
            if (v instanceof ListVal l) {
                var sb = new StringBuilder();
                sb.append('[');
                for (int i = 0; i < l.v.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(stringify(l.v.get(i)));
                }
                sb.append(']');
                return sb.toString();
            }
            if (v instanceof MapVal m) {
                var sb = new StringBuilder();
                sb.append('{');
                int i = 0;
                for (var e : m.v.entrySet()) {
                    if (i++ > 0) sb.append(", ");
                    sb.append(e.getKey()).append(": ").append(stringify(e.getValue()));
                }
                sb.append('}');
                return sb.toString();
            }
            return v.toString();
        }
    }

    static final class Json {
        private final String s;
        private final int n;
        private int i;

        private Json(String s) { this.s = s; this.n = s.length(); }

        static Val parse(String s) {
            var p = new Json(s);
            p.skip();
            Val v = p.value();
            p.skip();
            if (!p.eof()) throw new SableError("runtime: json trailing characters");
            return v;
        }

        static String stringify(Val v) {
            var sb = new StringBuilder();
            write(sb, v);
            return sb.toString();
        }

        private static void write(StringBuilder sb, Val v) {
            if (v == NullVal.INSTANCE) { sb.append("null"); return; }
            if (v instanceof Bool b) { sb.append(b.v ? "true" : "false"); return; }
            if (v instanceof Num n) {
                double x = n.v;
                if (Double.isNaN(x) || Double.isInfinite(x)) { sb.append("null"); return; }
                String t = Double.toString(x);
                if (t.endsWith(".0")) t = t.substring(0, t.length() - 2);
                sb.append(t);
                return;
            }
            if (v instanceof Str s) {
                sb.append('"');
                for (int k = 0; k < s.v.length(); k++) {
                    char c = s.v.charAt(k);
                    switch (c) {
                        case '"': sb.append("\\\""); break;
                        case '\\': sb.append("\\\\"); break;
                        case '\n': sb.append("\\n"); break;
                        case '\r': sb.append("\\r"); break;
                        case '\t': sb.append("\\t"); break;
                        default:
                            if (c < 32) {
                                sb.append(String.format("\\u%04x", (int) c));
                            } else {
                                sb.append(c);
                            }
                    }
                }
                sb.append('"');
                return;
            }
            if (v instanceof ListVal l) {
                sb.append('[');
                for (int k = 0; k < l.v.size(); k++) {
                    if (k > 0) sb.append(',');
                    write(sb, l.v.get(k));
                }
                sb.append(']');
                return;
            }
            if (v instanceof MapVal m) {
                sb.append('{');
                int k = 0;
                for (var e : m.v.entrySet()) {
                    if (k++ > 0) sb.append(',');
                    write(sb, new Str(e.getKey()));
                    sb.append(':');
                    write(sb, e.getValue());
                }
                sb.append('}');
                return;
            }
            sb.append('"').append("<").append(v.type()).append(">").append('"');
        }

        private Val value() {
            skip();
            if (eof()) throw new SableError("runtime: json unexpected eof");
            char c = peek();
            if (c == '"') return new Str(string());
            if (c == '{') return object();
            if (c == '[') return array();
            if (c == 't') { expect("true"); return new Bool(true); }
            if (c == 'f') { expect("false"); return new Bool(false); }
            if (c == 'n') { expect("null"); return NullVal.INSTANCE; }
            if (c == '-' || isDigit(c)) return new Num(number());
            throw new SableError("runtime: json unexpected char: " + c);
        }

        private MapVal object() {
            expect('{');
            skip();
            var map = new LinkedHashMap<String, Val>();
            if (peek() == '}') { i++; return new MapVal(map); }
            while (true) {
                skip();
                String k = string();
                skip();
                expect(':');
                Val v = value();
                map.put(k, v);
                skip();
                if (peek() == '}') { i++; break; }
                expect(',');
            }
            return new MapVal(map);
        }

        private ListVal array() {
            expect('[');
            skip();
            var list = new ArrayList<Val>();
            if (peek() == ']') { i++; return new ListVal(list); }
            while (true) {
                Val v = value();
                list.add(v);
                skip();
                if (peek() == ']') { i++; break; }
                expect(',');
            }
            return new ListVal(list);
        }

        private double number() {
            int start = i;
            if (peek() == '-') i++;
            while (!eof() && isDigit(peek())) i++;
            if (!eof() && peek() == '.') {
                i++;
                while (!eof() && isDigit(peek())) i++;
            }
            if (!eof() && (peek() == 'e' || peek() == 'E')) {
                i++;
                if (!eof() && (peek() == '+' || peek() == '-')) i++;
                while (!eof() && isDigit(peek())) i++;
            }
            String t = s.substring(start, i);
            try { return Double.parseDouble(t); } catch (Exception e) { throw new SableError("runtime: json invalid number"); }
        }

        private String string() {
            expect('"');
            var sb = new StringBuilder();
            while (!eof()) {
                char c = next();
                if (c == '"') break;
                if (c == '\\') {
                    if (eof()) throw new SableError("runtime: json bad escape");
                    char e = next();
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (i + 4 > n) throw new SableError("runtime: json bad unicode");
                            String hex = s.substring(i, i + 4);
                            i += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                            break;
                        default:
                            throw new SableError("runtime: json bad escape");
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private void expect(String kw) {
            for (int k = 0; k < kw.length(); k++) {
                if (eof() || s.charAt(i) != kw.charAt(k)) throw new SableError("runtime: json expected '" + kw + "'");
                i++;
            }
        }

        private void expect(char c) {
            skip();
            if (eof() || s.charAt(i) != c) throw new SableError("runtime: json expected '" + c + "'");
            i++;
        }

        private void skip() {
            while (!eof()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') i++;
                else break;
            }
        }

        private boolean eof() { return i >= n; }
        private char peek() { return eof() ? '\0' : s.charAt(i); }
        private char next() { return s.charAt(i++); }
        private static boolean isDigit(char c) { return c >= '0' && c <= '9'; }
    }
}
