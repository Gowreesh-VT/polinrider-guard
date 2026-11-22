/** Names come from the command line and from GitHub. They end up in git arguments, URLs and file paths, so check them. */

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;

export function parseRepo(input: string): string {
  const parts = input.split("/");
  const [owner, name] = parts;
  if (parts.length !== 2 || !owner || !name || !OWNER.test(owner) || !REPO.test(name) || name === "." || name === ".." || name.startsWith("-")) {
    throw new Error(`Not a valid repository name: "${input.slice(0, 80)}". Use owner/name.`);
  }
  return `${owner}/${name}`;
}

export function parseLogin(input: string): string {
  if (!OWNER.test(input)) throw new Error(`Not a valid GitHub username: "${input.slice(0, 60)}".`);
  return input;
}
