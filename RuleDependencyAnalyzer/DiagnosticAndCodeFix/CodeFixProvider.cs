using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DiagnosticAndCodeFix
{
    [ExportCodeFixProvider(DiagnosticAnalyzer.VersionTooLowId, LanguageNames.CSharp)]
    public class CodeFixProvider : ICodeFixProvider
    {
        public IEnumerable<string> GetFixableDiagnosticIds()
        {
            return new[] { DiagnosticAnalyzer.VersionTooLowId };
        }

        public Task<IEnumerable<CodeAction>> GetFixesAsync(Document document, TextSpan span, IEnumerable<Diagnostic> diagnostics, CancellationToken cancellationToken)
        {
            ImmutableArray<CodeAction>.Builder result = ImmutableArray.CreateBuilder<CodeAction>();
            foreach (Diagnostic diagnostic in diagnostics)
            {
                // Return a code action that will invoke the fix.
                result.Add(CodeAction.Create("Update version number", innerCancellationToken => UpdateVersionAsync(document, diagnostic.Location, innerCancellationToken)));
            }

            return Task.FromResult<IEnumerable<CodeAction>>(result.ToImmutable());
        }

        private async Task<Document> UpdateVersionAsync(Document document, Location location, CancellationToken cancellationToken)
        {
            var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);

            // Find the attribute syntax identified by the diagnostic.
            var attributeSyntax = root.FindToken(location.SourceSpan.Start).Parent.AncestorsAndSelf().OfType<AttributeSyntax>().FirstOrDefault();
            if (attributeSyntax == null)
                return document;

            var versionArgumentExpression = attributeSyntax.ArgumentList.Arguments[2].Expression;
            var newRoot = root.ReplaceNode(versionArgumentExpression, SyntaxFactory.LiteralExpression(SyntaxKind.NumericLiteralExpression, SyntaxFactory.Literal(100)));
            return document.WithSyntaxRoot(newRoot);
        }
    }
}
