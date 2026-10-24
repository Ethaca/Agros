#!/usr/bin/env tsx
import { Command } from "commander";

const program = new Command();
program.name("argos").description("Prove, vouch, and plug access-control checks");

program.command("init <repo>").description("Draft argos.config.yaml for a repo").action(() => {
  console.log("argos init: not implemented yet");
});
program.command("scan").description("Run persona x resource attack matrix").action(() => {
  console.log("argos scan: not implemented yet");
});
program.command("fix").description("Patch findings and re-run attacks").action(() => {
  console.log("argos fix: not implemented yet");
});
program.command("report").description("Write evidence report").action(() => {
  console.log("argos report: not implemented yet");
});

program.parse();
