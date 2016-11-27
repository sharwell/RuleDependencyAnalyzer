namespace RuleDependencyAnalyzer
{
    using System.Collections.Immutable;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.CodeAnalysis;
    using Microsoft.CodeAnalysis.CodeActions;
    using Microsoft.CodeAnalysis.CodeFixes;
    using Microsoft.CodeAnalysis.CSharp;
    using Microsoft.CodeAnalysis.CSharp.Syntax;

    [ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(VersionMismatchCodeFixProvider))]
    internal class VersionMismatchCodeFixProvider : CodeFixProvider
    {
        public override ImmutableArray<string> FixableDiagnosticIds
        {
            get
            {
                return ImmutableArray.Create(RuleDependencyDiagnosticAnalyzer.VersionTooHighId, RuleDependencyDiagnosticAnalyzer.VersionTooLowId);
            }
        }

        public override Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            ImmutableArray<CodeAction>.Builder result = ImmutableArray.CreateBuilder<CodeAction>();
            foreach (Diagnostic diagnostic in context.Diagnostics)
            {
                string expectedVersion;
                if (!diagnostic.Properties.TryGetValue("expected", out expectedVersion))
                    continue;

                int expectedVersionNumber;
                if (!int.TryParse(expectedVersion, out expectedVersionNumber))
                    continue;

                // Return a code action that will invoke the fix.
                context.RegisterCodeFix(CodeAction.Create("Update version number", cancellationToken => UpdateVersionAsync(context.Document, diagnostic.Location, expectedVersionNumber, cancellationToken)), diagnostic);
            }

            return Task.FromResult(true);
        }

        private async Task<Document> UpdateVersionAsync(Document document, Location location, int expectedVersion, CancellationToken cancellationToken)
        {
            var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);

            // Find the attribute syntax identified by the diagnostic.
            var attributeSyntax = root.FindToken(location.SourceSpan.Start).Parent.AncestorsAndSelf().OfType<AttributeSyntax>().FirstOrDefault();
            if (attributeSyntax == null)
                return document;

            var versionArgumentExpression = attributeSyntax.ArgumentList.Arguments[2].Expression;
            var newRoot = root.ReplaceNode(versionArgumentExpression, SyntaxFactory.LiteralExpression(SyntaxKind.NumericLiteralExpression, SyntaxFactory.Literal(expectedVersion)));
            return document.WithSyntaxRoot(newRoot);
        }
    }
}
