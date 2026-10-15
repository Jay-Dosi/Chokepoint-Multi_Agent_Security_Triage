# CHOKEPOINT. Everything runs through docker compose.

COMPOSE ?= docker compose
SCALE   ?= 1

.PHONY: up down seed logs mcp-stdio delta evals health rebuild typecheck lint clean

up: ## Build and start falkordb, mcp, backend and frontend
	$(COMPOSE) up --build -d
	@echo "CHOKEPOINT is starting. Open http://localhost:8080"
	@echo "API http://localhost:8000/api/health  ·  FalkorDB browser http://localhost:3000"

down: ## Stop everything and remove the containers
	$(COMPOSE) down

rebuild: ## Rebuild the images without cache
	$(COMPOSE) build --no-cache

seed: ## Drop and regenerate the graph (SCALE=1 by default)
	curl -fsS -X POST http://localhost:8000/api/seed/reset \
	  -H 'Content-Type: application/json' \
	  -d '{"scale": $(SCALE)}'
	@echo

delta: ## Apply the day-2 scan (scenario S7 and the S6 follow-up)
	curl -fsS -X POST http://localhost:8000/api/scan/delta
	@echo

evals: ## Run the evaluation and print the metrics
	curl -fsS http://localhost:8000/api/evals/run
	@echo

health: ## Print the health document
	curl -fsS http://localhost:8000/api/health
	@echo

logs: ## Follow the logs of every service
	$(COMPOSE) logs -f --tail=80

mcp-stdio: ## Run the MCP server on stdio against a local FalkorDB
	cd backend && FALKORDB_HOST=localhost GRAPH_NAME=chokepoint \
	  python -m mcp_server.server --transport stdio

typecheck: ## TypeScript check of the frontend
	cd frontend && npm install --no-audit --no-fund && npm run typecheck

lint: ## Ruff over the Python source
	cd backend && ruff check .

clean: ## Remove containers and the FalkorDB volume
	$(COMPOSE) down -v
