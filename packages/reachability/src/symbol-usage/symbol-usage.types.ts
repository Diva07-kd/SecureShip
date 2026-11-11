export type ImportBindingKind =
  | 'ESM_STATIC'
  | 'ESM_DYNAMIC'
  | 'CJS'
  | 'TS_IMPORT_EQUALS'
  | 'PYTHON_IMPORT'
  | 'PYTHON_FROM_IMPORT';

export interface ImportBinding {
  localName: string;
  importedName: 'default' | 'namespace' | string;
  rawSpecifier: string;
  packageRoot: string;
  subpath: string | null;
  kind: ImportBindingKind;
  line: number;
  isTypeOnly: boolean;
}

export type UsageForm =
  | 'call'
  | 'member_call'
  | 'new_call'
  | 'tagged_template'
  | 'member_access'
  | 'computed_access'
  | 'aliased_member'
  | 'destructured';

export interface SymbolUsageFact {
  packageRoot: string;
  symbol: string;
  form: UsageForm;
  file: string; // Relative POSIX path
  line: number;
  calleeExpression?: string;
  isCall: boolean;
  enclosingFunction?: string;
}

export type EscapeReason =
  | 'ARGUMENT_PASS'
  | 'RETURN'
  | 'EXPORT'
  | 'CONTAINER_STORE'
  | 'SPREAD'
  | 'ENUMERATION'
  | 'NON_LITERAL_COMPUTED'
  | 'REASSIGNMENT'
  | 'DYNAMIC_IMPORT'
  | 'WILDCARD_IMPORT'
  | 'REEXPORT_ALL'
  | 'CALLABLE_MODULE'
  | 'CREATE_REQUIRE'
  | 'UNKNOWN_SUBPATH';

export interface EscapeFact {
  packageRoot: string;
  reason: EscapeReason;
  file: string; // Relative POSIX path
  line: number;
  detail?: string;
}

export interface FileSymbolUsage {
  filePath: string; // Absolute path
  relativePath: string; // Relative POSIX path
  bindings: ImportBinding[];
  usageFacts: SymbolUsageFact[];
  escapes: EscapeFact[];
  hasCreateRequire: boolean;
  usageIncomplete: boolean;
  incompleteReason?: string;
}
