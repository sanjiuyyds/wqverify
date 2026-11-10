//
//  App.swift
//  Entry point for the WQDiag build. The dashboard itself lives in
//  DashboardView.swift so the wqverify target can share it.
//

import SwiftUI

@main
struct WQDiagApp: App {
    var body: some Scene {
        WindowGroup {
            DashboardView()
        }
    }
}