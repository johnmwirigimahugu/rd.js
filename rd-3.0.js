// rd-3.0.js - Advanced Dependency-Free ORM Framework
const { createServer } = require('http');
const { parse } = require('url');
const { randomUUID } = require('crypto');
const fs = require('fs').promises;
const path = require('path');

class Rd {
  constructor() {
    this._middleware = [];
    this._routes = {};
    this._defaultHeaders = {};
    this._errorHandler = (err, req, res) => res.status(500).send('Server Error');
    this._dbPath = './.rd_data';
  }

  static create() {
    return new Rd();
  }

  // Advanced ORM Core =============================================
  static R = {
    _tables: {},
    _schemas: {},
    _relations: {},
    _transactionStack: [],
    _dbPath: './.rd_data',

    async setup(config = {}) {
      if (config.dbPath) this._dbPath = config.dbPath;
      await this._ensureDbDir();
      await this._loadSchemas();
      return this;
    },

    async _ensureDbDir() {
      try {
        await fs.access(this._dbPath);
      } catch {
        await fs.mkdir(this._dbPath, { recursive: true });
      }
    },

    async _loadSchemas() {
      try {
        const schemaFile = path.join(this._dbPath, '_schemas.json');
        const data = await fs.readFile(schemaFile);
        this._schemas = JSON.parse(data);
        
        // Load tables data
        await Promise.all(
          Object.keys(this._schemas).map(async (table) => {
            const tableFile = path.join(this._dbPath, `${table}.json`);
            try {
              const data = await fs.readFile(tableFile);
              this._tables[table] = JSON.parse(data);
            } catch {
              this._tables[table] = {};
            }
          })
        );
      } catch (err) {
        this._schemas = {};
      }
    },

    async _saveSchema() {
      const schemaFile = path.join(this._dbPath, '_schemas.json');
      await fs.writeFile(schemaFile, JSON.stringify(this._schemas));
    },

    // Schema Management
    async migrate(table, schema) {
      this._schemas[table] = schema;
      await this._saveSchema();
      
      if (!this._tables[table]) {
        this._tables[table] = {};
        await this._persistTable(table);
      }
      return this;
    },

    // Relations
    relate(parent, child, relationType = 'hasMany') {
      this._relations[parent] = this._relations[parent] || {};
      this._relations[parent][child] = relationType;
      return this;
    },

    // Transactions
    async transaction(callback) {
      const transactionId = randomUUID();
      const snapshot = JSON.parse(JSON.stringify(this._tables));
      
      this._transactionStack.push({ id: transactionId, snapshot });
      
      try {
        const result = await callback();
        this._transactionStack.pop();
        return result;
      } catch (err) {
        const current = this._transactionStack.pop();
        if (current) this._tables = current.snapshot;
        throw err;
      }
    },

    // Advanced Querying
    async find(table, conditions) {
      const results = await this.findAll(table);
      return results.filter(item => {
        return Object.entries(conditions).every(([key, val]) => {
          if (typeof val === 'object') {
            return this._matchCondition(item[key], val);
          }
          return item[key] === val;
        });
      });
    },

    _matchCondition(value, condition) {
      const operators = {
        $gt: (a, b) => a > b,
        $lt: (a, b) => a < b,
        $gte: (a, b) => a >= b,
        $lte: (a, b) => a <= b,
        $ne: (a, b) => a !== b,
        $in: (a, b) => b.includes(a),
        $like: (a, b) => new RegExp(b.replace(/%/g, '.*')).test(a)
      };

      return Object.entries(condition).every(([op, val]) => {
        return operators[op]?.(value, val) ?? false;
      });
    },

    // CRUD Operations
    async dispense(table) {
      if (!this._tables[table]) {
        await this.migrate(table, { id: 'string' });
      }
      return { id: randomUUID(), __type: table };
    },

    async store(bean) {
      const table = bean.__type;
      if (!this._tables[table]) await this.migrate(table, { id: 'string' });

      // Auto-schema
      const currentSchema = this._schemas[table];
      Object.keys(bean).forEach(key => {
        if (!currentSchema[key]) {
          currentSchema[key] = typeof bean[key];
          this._schemas[table] = currentSchema;
        }
      });

      this._tables[table][bean.id] = bean;
      await this._persistTable(table);
      return bean;
    },

    async load(table, id) {
      await this._loadTable(table);
      return this._tables[table]?.[id] || null;
    },

    async findAll(table) {
      await this._loadTable(table);
      return Object.values(this._tables[table] || {});
    },

    async trash(bean) {
      const table = bean.__type;
      delete this._tables[table][bean.id];
      await this._persistTable(table);
      return true;
    },

    // Relations Handling
    async link(parent, child) {
      const relation = this._relations[parent.__type]?.[child.__type];
      if (!relation) throw new Error('Relation not defined');

      const junctionTable = `${parent.__type}_${child.__type}`;
      const relationId = randomUUID();

      await this.store({
        __type: junctionTable,
        id: relationId,
        [`${parent.__type}_id`]: parent.id,
        [`${child.__type}_id`]: child.id
      });

      return relationId;
    },

    async findRelated(parent, childType) {
      const junctionTable = `${parent.__type}_${childType}`;
      const relations = await this.findAll(junctionTable);
      const childIds = relations.map(r => r[`${childType}_id`]);
      
      return Promise.all(
        childIds.map(id => this.load(childType, id))
      );
    },

    // Persistence
    async _loadTable(table) {
      if (!this._tables[table]) {
        const tableFile = path.join(this._dbPath, `${table}.json`);
        try {
          const data = await fs.readFile(tableFile);
          this._tables[table] = JSON.parse(data);
        } catch {
          this._tables[table] = {};
        }
      }
    },

    async _persistTable(table) {
      const tableFile = path.join(this._dbPath, `${table}.json`);
      await fs.writeFile(tableFile, JSON.stringify(this._tables[table]));
    },

    // Migration Helpers
    async exportSchema() {
      return this._schemas;
    },

    async importSchema(schemas) {
      this._schemas = schemas;
      await this._saveSchema();
    }
  };

  // Framework Core ================================================
  setupORM(config = {}) {
    Rd.R._dbPath = config.dbPath || './.rd_data';
    return Rd.R.setup(config);
  }

  autoRoute(basePath = '/api') {
    this.use(async (req, res, next) => {
      const { pathname } = parse(req.url);
      if (!pathname.startsWith(basePath)) return next();

      const pathParts = pathname.replace(basePath, '').split('/');
      const [table, id, relation] = pathParts.filter(Boolean);

      try {
        let body = '';
        req.on('data', chunk => body += chunk);
        await new Promise(resolve => req.on('end', resolve));

        // Handle relations
        if (relation && id) {
          return this._handleRelations(req, res, table, id, relation);
        }

        switch(req.method) {
          case 'GET':
            if (id) {
              const result = await Rd.R.load(table, id);
              res.end(JSON.stringify(result));
            } else {
              const results = await Rd.R.findAll(table);
              res.end(JSON.stringify(results));
            }
            break;

          case 'POST':
            const newBean = Rd.R.dispense(table);
            Object.assign(newBean, JSON.parse(body));
            await Rd.R.store(newBean);
            res.writeHead(201);
            res.end(JSON.stringify(newBean));
            break;

          case 'PUT':
            const existing = await Rd.R.load(table, id);
            Object.assign(existing, JSON.parse(body));
            await Rd.R.store(existing);
            res.end(JSON.stringify(existing));
            break;

          case 'DELETE':
            await Rd.R.trash({ __type: table, id });
            res.writeHead(204);
            res.end();
            break;
        }
      } catch (err) {
        this._errorHandler(err, req, res);
      }
    });
    return this;
  }

  async _handleRelations(req, res, parentType, parentId, relation) {
    const parent = await Rd.R.load(parentType, parentId);
    if (!parent) return res.status(404).end();

    switch(req.method) {
      case 'GET':
        const related = await Rd.R.findRelated(parent, relation);
        res.end(JSON.stringify(related));
        break;

      case 'POST':
        const child = JSON.parse(req.body);
        const childBean = await Rd.R.dispense(relation);
        Object.assign(childBean, child);
        await Rd.R.store(childBean);
        await Rd.R.link(parent, childBean);
        res.writeHead(201);
        res.end(JSON.stringify(childBean));
        break;
    }
  }

  // Original Framework Methods ====================================
  use(middleware) { this._middleware.push(middleware); return this; }
  method(verb) { return (path, handler) => { this._routes[`${verb.toUpperCase()} ${path}`] = { handler, middleware: [...this._middleware] }; return this; }; }
  get(path, handler) { return this.method('get')(path, handler); }
  post(path, handler) { return this.method('post')(path, handler); }
  put(path, handler) { return this.method('put')(path, handler); }
  delete(path, handler) { return this.method('delete')(path, handler); }
  header(name, value) { if (value === undefined) return this._defaultHeaders[name]; this._defaultHeaders[name] = value; return this; }
  onError(handler) { this._errorHandler = handler; return this; }

  listen(port, callback) {
    const server = createServer(async (req, res) => {
      Object.entries(this._defaultHeaders).forEach(([name, value]) => res.setHeader(name, value));
      
      const routeKey = `${req.method} ${req.url}`;
      const route = this._routes[
