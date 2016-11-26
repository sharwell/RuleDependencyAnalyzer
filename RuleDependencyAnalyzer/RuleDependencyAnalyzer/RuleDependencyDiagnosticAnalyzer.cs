namespace RuleDependencyAnalyzer
{
    using Antlr4.Runtime;
    using Antlr4.Runtime.Atn;
    using Microsoft.CodeAnalysis;
    using Microsoft.CodeAnalysis.CSharp;
    using Microsoft.CodeAnalysis.CSharp.Syntax;
    using Microsoft.CodeAnalysis.Diagnostics;
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using Dependents = Antlr4.Runtime.Dependents;

    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class RuleDependencyDiagnosticAnalyzer : DiagnosticAnalyzer
    {
        internal const string AntlrCategory = "ANTLR";

        public const string UnknownRuleId = "AA2000";
        internal const string UnknownRuleTitle = "Unknown rule";
        internal const string UnknownRuleDescription = "A rule dependency specifies a rule index which was not found in the parser";
        internal const string UnknownRuleMessageFormat = "Rule dependency on unknown rule '{0}' in '{1}'";
        internal static readonly DiagnosticDescriptor UnknownRule = new DiagnosticDescriptor(UnknownRuleId, UnknownRuleTitle, UnknownRuleMessageFormat, AntlrCategory, DiagnosticSeverity.Warning, true, UnknownRuleDescription);

        public const string VersionTooHighId = "AA2001";
        internal const string VersionTooHighTitle = "Rule dependency version too high";
        internal const string VersionTooHighDescription = "A rule dependency specifies a version number which is higher than the maximum version of its dependent rules";
        internal const string VersionTooHighMessageFormat = "Rule dependency version mismatch: '{0}' has maximum dependency version {1} (expected {2}) in {3}";
        internal static readonly DiagnosticDescriptor VersionTooHigh = new DiagnosticDescriptor(VersionTooHighId, VersionTooHighTitle, VersionTooHighMessageFormat, AntlrCategory, DiagnosticSeverity.Error, true, VersionTooHighDescription);

        public const string NotImplementedAxisId = "AA2002";
        internal const string NotImplementedAxisTitle = "Dependency axis not yet implemented";
        internal const string NotImplementedAxisDescription = "A rule dependency specifies a Dependants axis which is not yet supported by this analyzer. The version is only partially checked.";
        internal const string NotImplementedAxisMessageFormat = "Analysis for the following dependents of rule '{0}' are not yet implemented: {1}";
        internal static readonly DiagnosticDescriptor NotImplementedAxis = new DiagnosticDescriptor(NotImplementedAxisId, NotImplementedAxisTitle, NotImplementedAxisMessageFormat, AntlrCategory, DiagnosticSeverity.Warning, true, NotImplementedAxisDescription);

        public const string VersionTooLowId = "AA2003";
        internal const string VersionTooLowTitle = "Rule dependency version too low";
        internal const string VersionTooLowDescription = "A rule dependency specifies a version number which is lower than the version of a dependent rule";
        internal const string VersionTooLowMessageFormat = "Declared dependency version {0}, but dependent {1} has newer version {2}";
        internal static readonly DiagnosticDescriptor VersionTooLow = new DiagnosticDescriptor(VersionTooLowId, VersionTooLowTitle, VersionTooLowMessageFormat, AntlrCategory, DiagnosticSeverity.Error, true, VersionTooLowDescription);

        public const string AnalysisErrorId = "AA2004";
        internal const string AnalysisErrorTitle = "Rule dependency analysis error";
        internal const string AnalysisErrorDescription = "A rule dependency declaration could not be analyzed due to an error in the source code or analyzer.";
        internal const string AnalysisErrorMessageFormat = "Rule dependency analysis failed: {0}";
        internal static readonly DiagnosticDescriptor AnalysisError = new DiagnosticDescriptor(AnalysisErrorId, AnalysisErrorTitle, AnalysisErrorMessageFormat, AntlrCategory, DiagnosticSeverity.Warning, true, AnalysisErrorDescription);

        public const string DiagnosticId = "DiagnosticAndCodeFix";

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        {
            get
            {
                return ImmutableArray.Create(UnknownRule, VersionTooHigh, NotImplementedAxis, VersionTooLow, AnalysisError);
            }
        }

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.ReportDiagnostics);

            Analyzer analyzer = new Analyzer();
            context.RegisterCompilationStartAction(analyzer.HandleCompilationStart);
        }

        private class Analyzer
        {
            private readonly Dictionary<INamedTypeSymbol, ImmutableArray<string>> _ruleNames = new Dictionary<INamedTypeSymbol, ImmutableArray<string>>();
            private readonly Dictionary<INamedTypeSymbol, ImmutableArray<int>> _ruleVersions = new Dictionary<INamedTypeSymbol, ImmutableArray<int>>();
            private readonly Dictionary<INamedTypeSymbol, RuleRelations> _ruleRelations = new Dictionary<INamedTypeSymbol, RuleRelations>();
            private INamedTypeSymbol _ruleDependencyAttribute;

            public void HandleCompilationStart(CompilationStartAnalysisContext context)
            {
                _ruleDependencyAttribute = context.Compilation.GetTypeByMetadataName(typeof(RuleDependencyAttribute).FullName);
                if (_ruleDependencyAttribute == null)
                    return;

                context.RegisterSyntaxNodeAction(HandleAttributeSyntax, SyntaxKind.Attribute);
            }

            private void HandleAttributeSyntax(SyntaxNodeAnalysisContext context)
            {
                AttributeSyntax attributeSyntax = (AttributeSyntax)context.Node;

                var attributeSymbol = context.SemanticModel.GetSymbolInfo(attributeSyntax, context.CancellationToken).Symbol;
                if (attributeSymbol == null)
                    return;

                if (!_ruleDependencyAttribute.Equals(((IMethodSymbol)attributeSymbol).ContainingType))
                    return;

                var targetSymbol = context.SemanticModel.GetDeclaredSymbol(attributeSyntax.Parent.Parent, context.CancellationToken);
                if (targetSymbol == null)
                    return;

                AttributeData attributeData = null;
                foreach (var data in targetSymbol.GetAttributes())
                {
                    if (data.ApplicationSyntaxReference.GetSyntax(context.CancellationToken) == attributeSyntax)
                    {
                        attributeData = data;
                        break;
                    }
                }

                if (attributeData == null)
                    return;

                var recognizerType = GetRecognizerType(attributeData);
                if (recognizerType == null)
                    return;

                foreach (var diagnostic in CheckDependencies((CSharpCompilation)context.Compilation, attributeData, recognizerType))
                {
                    context.ReportDiagnostic(diagnostic);
                }
            }

            private ImmutableArray<Diagnostic> CheckDependencies(CSharpCompilation compilation, AttributeData dependency, INamedTypeSymbol recognizerType)
            {
                ImmutableArray<string>? ruleNamesOpt = GetRuleNames(recognizerType);
                if (ruleNamesOpt == null)
                {
                    Location location = GetRecognizerTypeLocation(dependency);
                    return ImmutableArray.Create(Diagnostic.Create(AnalysisError, location, "could not read rule names from generated parser"));
                }

                ImmutableArray<int>? ruleVersionsOpt = GetRuleVersions(recognizerType);
                if (ruleVersionsOpt == null)
                {
                    Location location = GetRecognizerTypeLocation(dependency);
                    return ImmutableArray.Create(Diagnostic.Create(AnalysisError, location, "could not read rule versions from generated parser"));
                }

                RuleRelations relations = GetRuleRelations(recognizerType);
                if (relations == null)
                {
                    Location location = GetRecognizerTypeLocation(dependency);
                    return ImmutableArray.Create(Diagnostic.Create(AnalysisError, location, "could not read the ATN from the generated parser"));
                }

                if (!compilation.ClassifyConversion(recognizerType, GetRecognizerType(dependency)).IsImplicit)
                {
                    Location location = GetRecognizerTypeLocation(dependency);
                    return ImmutableArray.Create(Diagnostic.Create(AnalysisError, location, string.Format("could not convert '{0}' to '{1}'", recognizerType, GetRecognizerType(dependency))));
                }

                ImmutableArray<string> ruleNames = ruleNamesOpt.Value;
                ImmutableArray<int> ruleVersions = ruleVersionsOpt.Value;

                // this is the rule in the dependency set with the highest version number
                int effectiveRule = GetRule(dependency);
                if (effectiveRule < 0 || effectiveRule >= ruleVersions.Length)
                {
                    Location location = GetRuleLocation(dependency);
                    return ImmutableArray.Create(Diagnostic.Create(UnknownRule, location, GetRule(dependency), GetRecognizerType(dependency)));
                }

                ImmutableArray<Diagnostic>.Builder errors = ImmutableArray.CreateBuilder<Diagnostic>();

                Dependents dependents = Dependents.Self | (GetDependents(dependency) ?? Dependents.Parents);
                bool containsUnimplemented = ReportUnimplementedDependents(errors, dependency, ruleNames, dependents);
                bool[] @checked = new bool[ruleNames.Length];
                int highestRequiredDependency = CheckDependencyVersion(errors, dependency, ruleNames, ruleVersions, effectiveRule, null);
                if ((dependents & Dependents.Parents) != 0)
                {
                    bool[] parents = relations.parents[GetRule(dependency)];
                    for (int parent = Array.IndexOf(parents, true, 0); parent >= 0; parent = Array.IndexOf(parents, true, parent + 1))
                    {
                        if (parent >= ruleVersions.Length)
                        {
                            errors.Add(Diagnostic.Create(AnalysisError, GetLocation(dependency), "parent index out of range during analysis"));
                            continue;
                        }

                        if (@checked[parent])
                            continue;

                        @checked[parent] = true;
                        int required = CheckDependencyVersion(errors, dependency, ruleNames, ruleVersions, parent, "parent");
                        highestRequiredDependency = Math.Max(highestRequiredDependency, required);
                    }
                }

                if ((dependents & Dependents.Children) != 0)
                {
                    bool[] children = relations.children[GetRule(dependency)];
                    for (int child = Array.IndexOf(children, true, 0); child >= 0; child = Array.IndexOf(children, true, child + 1))
                    {
                        if (child >= ruleVersions.Length)
                        {
                            errors.Add(Diagnostic.Create(AnalysisError, GetLocation(dependency), "child index out of range during analysis"));
                            continue;
                        }

                        if (@checked[child])
                            continue;

                        @checked[child] = true;
                        int required = CheckDependencyVersion(errors, dependency, ruleNames, ruleVersions, child, "child");
                        highestRequiredDependency = Math.Max(highestRequiredDependency, required);
                    }
                }

                if ((dependents & Dependents.Ancestors) != 0)
                {
                    bool[] ancestors = relations.GetAncestors(GetRule(dependency));
                    for (int ancestor = Array.IndexOf(ancestors, true, 0); ancestor >= 0; ancestor = Array.IndexOf(ancestors, true, ancestor + 1))
                    {
                        if (ancestor >= ruleVersions.Length)
                        {
                            errors.Add(Diagnostic.Create(AnalysisError, GetLocation(dependency), "ancestor index out of range during analysis"));
                            continue;
                        }

                        if (@checked[ancestor])
                            continue;

                        @checked[ancestor] = true;
                        int required = CheckDependencyVersion(errors, dependency, ruleNames, ruleVersions, ancestor, "ancestor");
                        highestRequiredDependency = Math.Max(highestRequiredDependency, required);
                    }
                }

                if ((dependents & Dependents.Descendants) != 0)
                {
                    bool[] descendants = relations.GetDescendants(GetRule(dependency));
                    for (int descendant = Array.IndexOf(descendants, true, 0); descendant >= 0; descendant = Array.IndexOf(descendants, true, descendant + 1))
                    {
                        if (descendant >= ruleVersions.Length)
                        {
                            errors.Add(Diagnostic.Create(AnalysisError, GetLocation(dependency), "descendant index out of range during analysis"));
                            continue;
                        }

                        if (@checked[descendant])
                            continue;

                        @checked[descendant] = true;
                        int required = CheckDependencyVersion(errors, dependency, ruleNames, ruleVersions, descendant, "descendant");
                        highestRequiredDependency = Math.Max(highestRequiredDependency, required);
                    }
                }

                int declaredVersion = GetVersion(dependency);
                if (declaredVersion > highestRequiredDependency && !containsUnimplemented)
                {
                    Location location = Location.Create(dependency.ApplicationSyntaxReference.SyntaxTree, dependency.ApplicationSyntaxReference.Span);
                    var properties = ImmutableDictionary<string, string>.Empty.Add("expected", highestRequiredDependency.ToString());
                    errors.Add(Diagnostic.Create(VersionTooHigh, location, properties, ruleNames[GetRule(dependency)], highestRequiredDependency, declaredVersion, GetRecognizerType(dependency)));
                }

                return errors.ToImmutable();
            }

            private ImmutableArray<string>? GetRuleNames(INamedTypeSymbol recognizerType)
            {
                ImmutableArray<string> ruleNames;
                if (!_ruleNames.TryGetValue(recognizerType, out ruleNames))
                {
                    ImmutableArray<string>? ruleNamesOpt = RuleDependencyDiagnosticAnalyzer.GetRuleNames(recognizerType);
                    if (ruleNamesOpt == null)
                        return null;

                    ruleNames = ruleNamesOpt.Value;
                    _ruleNames[recognizerType] = ruleNames;
                }

                return ruleNames;
            }

            private ImmutableArray<int>? GetRuleVersions(INamedTypeSymbol recognizerType)
            {
                ImmutableArray<int> ruleVersions;
                if (!_ruleVersions.TryGetValue(recognizerType, out ruleVersions))
                {
                    ImmutableArray<string>? ruleNames = GetRuleNames(recognizerType);
                    if (ruleNames == null)
                        return null;

                    ImmutableArray<int>? ruleVersionsOpt = RuleDependencyDiagnosticAnalyzer.GetRuleVersions(recognizerType, ruleNames.Value);
                    if (ruleVersionsOpt == null)
                        return null;

                    ruleVersions = ruleVersionsOpt.Value;
                    _ruleVersions[recognizerType] = ruleVersions;
                }

                return ruleVersions;
            }

            private RuleRelations GetRuleRelations(INamedTypeSymbol recognizerType)
            {
                RuleRelations ruleRelations;
                if (!_ruleRelations.TryGetValue(recognizerType, out ruleRelations))
                {
                    ruleRelations = ExtractRuleRelations(recognizerType);
                    _ruleRelations[recognizerType] = ruleRelations;
                }

                return ruleRelations;
            }
        }

        private static Location GetLocation(AttributeData attributeData)
        {
            var syntax = attributeData.ApplicationSyntaxReference;
            return Location.Create(syntax.SyntaxTree, syntax.Span);
        }

        private static INamedTypeSymbol GetRecognizerType(AttributeData attributeData)
        {
            var recognizerParameter = attributeData.AttributeConstructor.Parameters.FirstOrDefault();
            if (recognizerParameter.Name != "recognizer")
                return null;

            TypedConstant recognizerConstant = attributeData.ConstructorArguments[0];
            return recognizerConstant.Value as INamedTypeSymbol;
        }

        private static Location GetRecognizerTypeLocation(AttributeData attributeData)
        {
            INamedTypeSymbol recognizerType = GetRecognizerType(attributeData);
            if (recognizerType == null)
                return GetLocation(attributeData);

            var attributeSyntax = (AttributeSyntax)attributeData.ApplicationSyntaxReference.GetSyntax();
            var syntax = attributeSyntax.ArgumentList.Arguments[0];
            return Location.Create(syntax.SyntaxTree, syntax.Span);
        }

        private static int GetRule(AttributeData attributeData)
        {
            var ruleParameter = attributeData.AttributeConstructor.Parameters.ElementAtOrDefault(1);
            if (ruleParameter == null || ruleParameter.Name != "rule")
                return -1;

            TypedConstant ruleConstant = attributeData.ConstructorArguments[1];
            return (int)ruleConstant.Value;
        }

        private static Location GetRuleLocation(AttributeData attributeData)
        {
            int ruleIndex = GetRule(attributeData);
            if (ruleIndex < 0)
                return GetLocation(attributeData);

            var attributeSyntax = (AttributeSyntax)attributeData.ApplicationSyntaxReference.GetSyntax();
            var syntax = attributeSyntax.ArgumentList.Arguments[1];
            return Location.Create(syntax.SyntaxTree, syntax.Span);
        }

        private static int GetVersion(AttributeData attributeData)
        {
            var versionParameter = attributeData.AttributeConstructor.Parameters.ElementAtOrDefault(2);
            if (versionParameter == null || versionParameter.Name != "version")
                return 0;

            TypedConstant versionConstant = attributeData.ConstructorArguments[2];
            return (int)versionConstant.Value;
        }

        private static Dependents? GetDependents(AttributeData attributeData)
        {
            var dependentsParameter = attributeData.AttributeConstructor.Parameters.ElementAtOrDefault(3);
            if (dependentsParameter == null || dependentsParameter.Name != "dependents")
                return null;

            TypedConstant dependentsConstant = attributeData.ConstructorArguments[3];
            return (Dependents)(int)dependentsConstant.Value;
        }

        private static Location GetDependentsLocation(AttributeData attributeData)
        {
            Dependents? dependents = GetDependents(attributeData);
            if (!dependents.HasValue)
                return GetLocation(attributeData);

            var attributeSyntax = (AttributeSyntax)attributeData.ApplicationSyntaxReference.GetSyntax();
            var syntax = attributeSyntax.ArgumentList.Arguments[3];
            return Location.Create(syntax.SyntaxTree, syntax.Span);
        }

        private static readonly Dependents ImplementedDependents = Dependents.Self | Dependents.Parents | Dependents.Children | Dependents.Ancestors | Dependents.Descendants;

        private static bool ReportUnimplementedDependents(IList<Diagnostic> errors, AttributeData dependency, ImmutableArray<string> ruleNames, Dependents dependents)
        {
            Dependents unimplemented = dependents;
            unimplemented &= ~ImplementedDependents;
            if (unimplemented != Dependents.None)
            {
                int ruleIndex = GetRule(dependency);
                string ruleName = ruleIndex >= 0 && ruleIndex < ruleNames.Length ? ruleNames[ruleIndex] : ruleIndex.ToString();
                Location location = GetDependentsLocation(dependency);
                errors.Add(Diagnostic.Create(NotImplementedAxis, location, ruleName, unimplemented));
                return true;
            }

            return false;
        }

        private static int CheckDependencyVersion(IList<Diagnostic> errors, AttributeData dependency, ImmutableArray<string> ruleNames, ImmutableArray<int> ruleVersions, int relatedRule, string relation)
        {
            string ruleName = ruleNames[GetRule(dependency)];
            string path;
            if (relation == null)
            {
                path = string.Format("rule '{0}'", ruleName);
            }
            else
            {
                string mismatchedRuleName = ruleNames[relatedRule];
                path = string.Format("rule '{0}' ({1} of '{2}')", mismatchedRuleName, relation, ruleName);
            }

            int declaredVersion = GetVersion(dependency);
            int actualVersion = ruleVersions[relatedRule];
            if (actualVersion > declaredVersion)
            {
                Location location = GetLocation(dependency);
                var properties = ImmutableDictionary<string, string>.Empty.Add("expected", actualVersion.ToString());
                errors.Add(Diagnostic.Create(VersionTooLow, location, properties, declaredVersion, path, actualVersion));
            }

            return actualVersion;
        }

        private static ImmutableArray<int> GetRuleVersions(INamedTypeSymbol recognizerType, ImmutableArray<string> ruleNames)
        {
            int?[] versions = new int?[ruleNames.Length];
            IFieldSymbol[] fields = recognizerType.GetMembers().OfType<IFieldSymbol>().ToArray();
            foreach (IFieldSymbol field in fields)
            {
                bool isConst = field.IsConst;
                bool isInteger = field.Type.SpecialType == SpecialType.System_Int32;
                if (isConst && isInteger && field.Name.StartsWith("RULE_"))
                {
                    string name = field.Name.Substring("RULE_".Length);
                    if (name.Length == 0 || !char.IsLower(name[0]))
                        continue;

                    int index = (int)field.ConstantValue;
                    if (index < 0 || index >= versions.Length)
                        continue;

                    IMethodSymbol ruleMethod = GetRuleMethod(recognizerType, name);
                    if (ruleMethod == null)
                        continue;

                    AttributeData ruleVersionData = ruleMethod.GetAttributes().Where(i => i.AttributeClass.Name == nameof(RuleVersionAttribute)).FirstOrDefault();
                    if (ruleVersionData == null || ruleVersionData.AttributeConstructor == null)
                        continue;

                    if (ruleVersionData.ConstructorArguments.Length == 0 || !(ruleVersionData.ConstructorArguments[0].Value is int))
                        continue;

                    int version = (int)ruleVersionData.ConstructorArguments[0].Value;
                    versions[index] = version;
                }
            }

            if (versions.Any(i => !i.HasValue) && recognizerType.BaseType != null)
            {
                ImmutableArray<int> inherited = GetRuleVersions(recognizerType.BaseType, ruleNames);
                for (int i = 0; i < versions.Length; i++)
                {
                    if (versions[i].HasValue)
                        continue;

                    versions[i] = inherited[i];
                }
            }

            return ImmutableArray.Create(Array.ConvertAll(versions, i => i ?? 0));
        }

        private static IMethodSymbol GetRuleMethod(INamedTypeSymbol recognizerType, string name)
        {
            for (INamedTypeSymbol currentType = recognizerType; currentType != null; currentType = currentType.BaseType)
            {
                foreach (var methodSymbol in currentType.GetMembers(name).OfType<IMethodSymbol>())
                {
                    if (methodSymbol.GetAttributes().Any(i => i.AttributeClass != null && i.AttributeClass.Name == nameof(RuleVersionAttribute)))
                        return methodSymbol;
                }
            }

            return null;
        }

        private static ImmutableArray<string>? GetRuleNames(INamedTypeSymbol recognizerType)
        {
            IFieldSymbol ruleNamesField = recognizerType.GetMembers("ruleNames").FirstOrDefault() as IFieldSymbol;
            if (ruleNamesField == null)
            {
                for (INamedTypeSymbol current = recognizerType.BaseType; ruleNamesField == null && current != null; current = current.BaseType)
                    ruleNamesField = current.GetMembers("ruleNames").FirstOrDefault() as IFieldSymbol;

                if (ruleNamesField == null)
                    return null;
            }

            var syntax = ruleNamesField.DeclaringSyntaxReferences.First().GetSyntax(CancellationToken.None) as VariableDeclaratorSyntax;
            var equalsValueClauseSyntax = syntax.Initializer;
            var valueSyntax = equalsValueClauseSyntax.Value as InitializerExpressionSyntax;
            ImmutableArray<string>.Builder ruleNames = ImmutableArray.CreateBuilder<string>();
            foreach (var expression in valueSyntax.Expressions)
            {
                LiteralExpressionSyntax literalSyntax = expression as LiteralExpressionSyntax;
                if (literalSyntax == null)
                    return null;

                string ruleName = literalSyntax.Token.Value as string;
                if (string.IsNullOrEmpty(ruleName))
                    return null;

                ruleNames.Add(ruleName);
            }

            return ruleNames.ToImmutable();
        }

        private static IEnumerable<INamedTypeSymbol> GetAllTypes(INamespaceOrTypeSymbol namespaceOrTypeSymbol)
        {
            foreach (var typeMember in namespaceOrTypeSymbol.GetTypeMembers())
            {
                foreach (var childType in GetAllTypes(typeMember))
                    yield return childType;

                yield return typeMember;
            }

            INamespaceSymbol namespaceSymbol = namespaceOrTypeSymbol as INamespaceSymbol;
            if (namespaceSymbol != null)
            {
                foreach (var childNamespace in namespaceSymbol.GetNamespaceMembers())
                {
                    foreach (var childType in GetAllTypes(childNamespace))
                        yield return childType;
                }
            }
        }

        private static RuleRelations ExtractRuleRelations(INamedTypeSymbol recognizerType)
        {
            string serializedATN = GetSerializedATN(recognizerType);
            if (serializedATN == null)
                return null;

            ATN atn = new ATNDeserializer().Deserialize(serializedATN.ToCharArray());
            RuleRelations relations = new RuleRelations(atn.ruleToStartState.Length);
            foreach (ATNState state in atn.states)
            {
                if (!state.epsilonOnlyTransitions)
                    continue;

                foreach (Transition transition in state.Transitions)
                {
                    RuleTransition ruleTransition = transition as RuleTransition;
                    if (ruleTransition == null)
                        continue;

                    relations.AddRuleInvocation(state.ruleIndex, ruleTransition.target.ruleIndex);
                }
            }

            return relations;
        }

        private static string GetSerializedATN(INamedTypeSymbol recognizerType)
        {
            IFieldSymbol serializedAtnField = recognizerType.GetMembers("_serializedATN").FirstOrDefault() as IFieldSymbol;
            if (serializedAtnField != null)
                return GetFixedValue(serializedAtnField);

            if (recognizerType.BaseType != null)
                return GetSerializedATN(recognizerType.BaseType);

            return null;
        }

        private static string GetFixedValue(IFieldSymbol fieldSymbol)
        {
            if (fieldSymbol.IsConst)
                return fieldSymbol.ConstantValue as string;

            var syntax = fieldSymbol.DeclaringSyntaxReferences.First().GetSyntax(CancellationToken.None) as VariableDeclaratorSyntax;
            var valueSyntax = syntax?.Initializer?.Value as LiteralExpressionSyntax;
            if (valueSyntax != null)
            {
                string value = valueSyntax?.Token.Value as string;
                return value;
            }

            if (syntax?.Initializer?.Value is BinaryExpressionSyntax)
            {
                Stack<ExpressionSyntax> stack = new Stack<ExpressionSyntax>();
                stack.Push(syntax?.Initializer.Value);
                StringBuilder builder = new StringBuilder();
                while (stack.Count > 0)
                {
                    ExpressionSyntax current = stack.Pop();

                    LiteralExpressionSyntax literal = current as LiteralExpressionSyntax;
                    if (literal != null)
                    {
                        string value = literal?.Token.Value as string;
                        if (value == null)
                            return null;

                        builder.Append(value);
                        continue;
                    }

                    BinaryExpressionSyntax binarySyntax = current as BinaryExpressionSyntax;
                    if (binarySyntax == null || !binarySyntax.IsKind(SyntaxKind.AddExpression))
                        return null;

                    stack.Push(binarySyntax.Right);
                    stack.Push(binarySyntax.Left);
                }

                return builder.ToString();
            }

            return null;
        }

        private sealed class RuleRelations
        {
            public readonly bool[][] parents;

            public readonly bool[][] children;

            public RuleRelations(int ruleCount)
            {
                parents = new bool[ruleCount][];
                for (int i = 0; i < ruleCount; i++)
                    parents[i] = new bool[ruleCount];

                children = new bool[ruleCount][];
                for (int i = 0; i < ruleCount; i++)
                    children[i] = new bool[ruleCount];
            }

            public bool AddRuleInvocation(int caller, int callee)
            {
                if (caller < 0)
                {
                    // tokens rule
                    return false;
                }

                if (children[caller][callee])
                {
                    // already added
                    return false;
                }

                children[caller][callee] = true;
                parents[callee][caller] = true;
                return true;
            }

            public bool[] GetAncestors(int rule)
            {
                bool[] ancestors = (bool[])parents[rule].Clone();
                while (true)
                {
                    int cardinality = ancestors.Count(i => i);
                    for (int i = Array.IndexOf(ancestors, true, 0); i >= 0; i = Array.IndexOf(ancestors, true, i + 1))
                    {
                        for (int j = 0; j < parents[i].Length; j++)
                            ancestors[j] |= parents[i][j];
                    }

                    if (cardinality == ancestors.Count(i => i))
                    {
                        // nothing changed
                        break;
                    }
                }

                return ancestors;
            }

            public bool[] GetDescendants(int rule)
            {
                bool[] descendants = (bool[])children[rule].Clone();
                while (true)
                {
                    int cardinality = descendants.Count(i => i);
                    for (int i = Array.IndexOf(descendants, true, 0); i >= 0; i = Array.IndexOf(descendants, true, i + 1))
                    {
                        for (int j = 0; j < parents[i].Length; j++)
                            descendants[j] |= parents[i][j];
                    }

                    if (cardinality == descendants.Count(i => i))
                    {
                        // nothing changed
                        break;
                    }
                }

                return descendants;
            }
        }
    }
}
