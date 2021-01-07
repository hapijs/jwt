
import * as Jwt from '..';
import { Plugin } from '@hapi/hapi';
import * as Lab from '@hapi/lab';

const { expect } = Lab.types;

expect.type<Plugin<void>>(Jwt);
