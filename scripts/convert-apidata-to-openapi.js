#!/usr/bin/env node
//
// Convert Proxmox VE API data (api-viewer/apidata.js) to OpenAPI 3.0 specification.
//
// Usage:
//   node scripts/convert-apidata-to-openapi.js [api-viewer/apidata.js] > api-viewer/pve-api-openapi.json
//

'use strict';

const fs = require('fs');
const path = require('path');

const inputFile = process.argv[2] ||
    path.join(__dirname, '..', 'api-viewer', 'apidata.js');

// ---------------------------------------------------------------------------
// 1. Load apidata.js – it defines `const apiSchema = [...]`;
//    We strip the variable declaration and parse the JSON array directly.
// ---------------------------------------------------------------------------
let src = fs.readFileSync(inputFile, 'utf8');

// Remove the "const apiSchema = " prefix and the trailing ";\n"
src = src.replace(/^\s*(?:const|var|let)\s+apiSchema\s*=\s*/, '');
src = src.replace(/;\s*$/, '');

let apiSchema;
try {
    apiSchema = JSON.parse(src);
} catch (e) {
    console.error('ERROR: could not parse apiSchema from', inputFile);
    console.error(e.message);
    process.exit(1);
}

if (!Array.isArray(apiSchema)) {
    console.error('ERROR: apiSchema is not an array in', inputFile);
    process.exit(1);
}

// ---------------------------------------------------------------------------
// 2. Helpers
// ---------------------------------------------------------------------------

const NUMERIC_KEYS = new Set(['minimum', 'maximum', 'maxLength', 'minLength']);

/** Deep-clone an object, coercing known numeric constraint fields to Number. */
function coerceNumericStrings(obj) {
    if (Array.isArray(obj)) return obj.map(coerceNumericStrings);
    if (obj !== null && typeof obj === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(obj)) {
            out[k] = NUMERIC_KEYS.has(k) && typeof v === 'string' ? Number(v) : coerceNumericStrings(v);
        }
        return out;
    }
    return obj;
}

/** Map of PVE type names to OpenAPI-compatible types. */
function mapType(pveType) {
    switch (pveType) {
        case 'string':  return { type: 'string' };
        case 'integer': return { type: 'integer' };
        case 'number':  return { type: 'number' };
        case 'boolean': return { type: 'boolean' };
        case 'array':   return { type: 'array' };
        case 'object':  return { type: 'object' };
        case 'null':    return {};             // no content
        default:        return { type: 'string' };
    }
}

/** Extract path parameter names from a path like /nodes/{node}/qemu/{vmid}. */
function extractPathParams(apiPath) {
    const matches = apiPath.match(/\{([^}]+)\}/g) || [];
    return matches.map(m => m.slice(1, -1));
}

/** Build an OpenAPI Schema Object from a PVE property descriptor. */
function buildSchemaForProperty(prop) {
    const schema = {};

    // type
    const mapped = mapType(prop.type);
    if (mapped.type) schema.type = mapped.type;

    // description
    if (prop.description) schema.description = prop.description;

    // enum
    if (prop.enum) schema.enum = prop.enum;

    // pattern
    if (prop.pattern) schema.pattern = prop.pattern;

    // numeric constraints – coerce to number (PVE source may have strings)
    if (prop.minimum !== undefined) schema.minimum = Number(prop.minimum);
    if (prop.maximum !== undefined) schema.maximum = Number(prop.maximum);

    // string constraints
    if (prop.maxLength !== undefined) schema.maxLength = Number(prop.maxLength);
    if (prop.minLength !== undefined) schema.minLength = Number(prop.minLength);

    // default
    if (prop.default !== undefined) schema.default = prop.default;

    // format – PVE uses either a string name or a structured object;
    // keep both forms under x-pve-format for transparency.
    if (prop.format) {
        if (typeof prop.format === 'string') {
            schema['x-pve-format'] = prop.format;
        } else {
            // Complex structured format definition – store as extension
            // Coerce any nested numeric constraint strings to numbers
            schema['x-pve-format'] = coerceNumericStrings(prop.format);
        }
    }

    // nested object
    if (prop.properties) {
        schema.type = 'object';
        schema.properties = {};
        const nestedRequired = [];
        for (const [k, v] of Object.entries(prop.properties)) {
            schema.properties[k] = buildSchemaForProperty(v);
            if (!v.optional) nestedRequired.push(k);
        }
        if (nestedRequired.length) schema.required = nestedRequired;
    }

    // array items
    if (prop.items) {
        schema.type = 'array';
        schema.items = buildSchemaForProperty(prop.items);
    }

    return schema;
}

/** Build the response object for an endpoint. */
function buildResponse(returns) {
    if (!returns || returns.type === 'null') {
        return {
            '200': {
                description: 'Successful response (no content).',
            },
        };
    }

    const schema = buildSchemaForProperty(returns);

    // Proxmox always wraps responses in { "data": <actual> }
    const wrapped = {
        type: 'object',
        properties: {
            data: Object.keys(schema).length ? schema : { description: 'Response data' },
        },
    };

    return {
        '200': {
            description: 'Successful response.',
            content: {
                'application/json': {
                    schema: wrapped,
                },
            },
        },
    };
}

/** Format a PVE permissions object into a human-readable string. */
function formatPermissions(perms) {
    if (!perms) return '';
    const parts = [];
    if (perms.description) parts.push(perms.description);
    if (perms.user) parts.push(`User: ${perms.user}`);
    if (perms.check) parts.push(`Check: ${JSON.stringify(perms.check)}`);
    return parts.join(' | ');
}

// ---------------------------------------------------------------------------
// 3. Traverse the tree and collect path+method entries
// ---------------------------------------------------------------------------
const paths = {};

function walk(node) {
    if (node.info) {
        const apiPath = node.path;
        if (!apiPath) return;

        const pathParams = extractPathParams(apiPath);

        if (!paths[apiPath]) paths[apiPath] = {};

        for (const [httpMethod, opInfo] of Object.entries(node.info)) {
            const method = httpMethod.toLowerCase();
            const operation = {};

            // operationId
            if (opInfo.name) {
                // Create a unique operationId from path + method name
                const pathId = apiPath.replace(/[{}\/]/g, '_').replace(/^_|_$/g, '');
                operation.operationId = `${pathId}_${opInfo.name}`;
            }

            // description
            if (opInfo.description) {
                operation.description = opInfo.description;
            }

            // tags – derive from first path segment
            const segments = apiPath.split('/').filter(Boolean);
            if (segments.length) {
                operation.tags = [segments[0]];
            }

            // permissions → added as x-pve-permissions and appended to description
            if (opInfo.permissions) {
                operation['x-pve-permissions'] = opInfo.permissions;
                const permStr = formatPermissions(opInfo.permissions);
                if (permStr) {
                    operation.description =
                        (operation.description || '') + `\n\nPermissions: ${permStr}`;
                }
            }

            // protected flag
            if (opInfo.protected) {
                operation['x-pve-protected'] = true;
            }

            // allowtoken
            if (opInfo.allowtoken !== undefined) {
                operation['x-pve-allowtoken'] = !!opInfo.allowtoken;
            }

            // ---- parameters & requestBody ----
            const params = [];
            const bodyProps = {};
            const bodyRequired = [];

            // Always add path parameters
            for (const pp of pathParams) {
                const paramDef = {
                    name: pp,
                    in: 'path',
                    required: true,
                    schema: { type: 'string' },
                };
                // Try to find a richer definition from the operation's parameters
                const props = opInfo.parameters && opInfo.parameters.properties;
                if (props && props[pp]) {
                    const rich = buildSchemaForProperty(props[pp]);
                    paramDef.schema = rich;
                    if (props[pp].description) paramDef.description = props[pp].description;
                }
                params.push(paramDef);
            }

            // Non-path parameters
            const props = opInfo.parameters && opInfo.parameters.properties;
            if (props) {
                for (const [name, def] of Object.entries(props)) {
                    if (pathParams.includes(name)) continue; // already handled
                    const schema = buildSchemaForProperty(def);

                    if (method === 'get' || method === 'delete') {
                        // query parameters
                        const p = { name, in: 'query', schema };
                        if (def.description) p.description = def.description;
                        if (!def.optional) p.required = true;
                        params.push(p);
                    } else {
                        // POST / PUT → request body
                        bodyProps[name] = schema;
                        if (!def.optional) bodyRequired.push(name);
                    }
                }
            }

            if (params.length) operation.parameters = params;

            if (Object.keys(bodyProps).length) {
                const bodySchema = { type: 'object', properties: bodyProps };
                if (bodyRequired.length) bodySchema.required = bodyRequired;
                operation.requestBody = {
                    content: {
                        'application/json': { schema: bodySchema },
                    },
                };
            }

            // ---- responses ----
            operation.responses = buildResponse(opInfo.returns);

            paths[apiPath][method] = operation;
        }
    }

    // recurse into children
    if (Array.isArray(node.children)) {
        for (const child of node.children) walk(child);
    }
}

// The top-level apiSchema is an array (usually one root element with children)
for (const root of apiSchema) walk(root);

// ---------------------------------------------------------------------------
// 4. Build the final OpenAPI document
// ---------------------------------------------------------------------------
const openapi = {
    openapi: '3.0.3',
    info: {
        title: 'Proxmox VE API',
        description:
            'Auto-generated OpenAPI specification for the Proxmox Virtual Environment REST API.\n' +
            'Converted from the PVE api-viewer schema (apidata.js).',
        version: '1.0.0',
        contact: {
            name: 'Proxmox',
            url: 'https://www.proxmox.com',
        },
        license: {
            name: 'GNU Affero General Public License v3.0',
            url: 'https://www.gnu.org/licenses/agpl-3.0.en.html',
        },
    },
    servers: [
        {
            url: 'https://{host}:{port}/api2/json',
            description: 'Proxmox VE API server',
            variables: {
                host: { default: 'localhost', description: 'PVE host address' },
                port: { default: '8006', description: 'PVE API port' },
            },
        },
    ],
    security: [
        { apiToken: [] },
        { cookie: [] },
    ],
    paths,
    components: {
        securitySchemes: {
            apiToken: {
                type: 'apiKey',
                in: 'header',
                name: 'Authorization',
                description:
                    'PVE API Token. Format: PVEAPIToken=USER@REALM!TOKENID=UUID',
            },
            cookie: {
                type: 'apiKey',
                in: 'cookie',
                name: 'PVEAuthCookie',
                description: 'PVE authentication cookie obtained via /access/ticket.',
            },
        },
    },
};

// ---------------------------------------------------------------------------
// 5. Output
// ---------------------------------------------------------------------------
const output = JSON.stringify(openapi, null, 2);
process.stdout.write(output + '\n');
