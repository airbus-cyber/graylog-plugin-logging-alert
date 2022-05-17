/*
 * Copyright (C) 2018 Airbus CyberSecurity (SAS)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

import React from 'react';
import { render } from 'wrappedTestingLibrary';
import { StoreMock as MockStore } from 'helpers/mocking';
import { adminUser } from 'fixtures/users';

import StoreProvider from 'injection/StoreProvider';
import CurrentUserContext from 'contexts/CurrentUserContext';

import LoggingAlertConfig from './LoggingAlertConfig';

const mockListStreams = jest.fn((...args) => Promise.resolve([]));

jest.mock('injection/CombinedProvider', () => ({
  get: jest.fn(() => ({ StreamsStore: { listStreams: (...args) => mockListStreams(...args) } })),
}));

describe('<LoggingAlertConfig>', () => {
  it('should display the button with the correct color (issue 33)', async () => {
    const { findByText } = render(<CurrentUserContext.Provider value={adminUser}>
                                    <LoggingAlertConfig updateConfig={jest.fn()} />
                                  </CurrentUserContext.Provider>);
    // TODO: I don't understand why getByText does not work here
    const elem = await findByText('Configure');
    expect(elem).toHaveStyle('background-color: rgb(0, 99, 190)')
  });
});