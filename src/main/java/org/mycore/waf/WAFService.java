package org.mycore.waf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;


public interface WAFService {

  /**
   * Checks if the Proof of Work mechanism is enabled.
   * @return true if enabled, false otherwise.
   */
  boolean isEnabled();

  /**
   * Checks if the incoming request has a valid Proof of Work cookie.
   * Cleans up any invalid cookies if necessary.
   * @param request the incoming HTTP request.
   * @return true if the cookie is valid, false otherwise.
   */
  boolean validateWAFPassedCookie(HttpServletRequest request);

  /**
   * Creates a valid Proof of Work cookie for the given request and adds it to the response.
   * @param request the incoming HTTP request.
   * @param response the outgoing HTTP response.
   */
  void createWAFPassedCookie(HttpServletRequest request, HttpServletResponse response);

  /**
   * Checks if the incoming request has a valid Proof of Work solution.
   * @param request the incoming HTTP request.
   * @return true if the solution is valid, false otherwise.
   */
  boolean hasSolution(HttpServletRequest request);


  /**
   * Generates a Proof of Work cookie for the given request and adds it to the response.
   * @param request the incoming HTTP request.
   * @param resp the outgoing Cookie
   */
  void generateChallenge(HttpServletRequest request, HttpServletResponse resp);

  /**
   * Redirects the client to the Proof of Work challenge page.
   * @param request the incoming HTTP request.
   * @param response the outgoing HTTP response.
   */
  void redirectToChallenge(HttpServletRequest request, HttpServletResponse response)
      throws IOException;

  boolean isChallengeRequest(HttpServletRequest request);

  boolean isChallengeSolutionRequest(HttpServletRequest request);

  /**
   * Validates the Proof of Work solution provided in the request.
   * @param request the incoming HTTP request.
   * @return true if the solution is valid, false otherwise.
   */
  boolean isValidSolution(HttpServletRequest request);

  /**
   * Redirects the user to the original URL after successfully completing the challenge.
   * @param request the incoming HTTP request.
   * @param response the outgoing HTTP response.
   * @throws IOException if an I/O error occurs.
   */
  void redirectAfterChallenge(HttpServletRequest request, HttpServletResponse response)
      throws IOException;

  /**
   * Redirects to the challenge page after a failed attempt, incrementing the attempt counter.
   * @param request the incoming HTTP request.
   * @param response the outgoing HTTP response.
   * @throws IOException if an I/O error occurs.
   */
  void redirectAfterFailedAttempt(HttpServletRequest request, HttpServletResponse response)
      throws IOException;

  /**
   * Checks if the IP address is on the allow list.
   * @param request the incoming HTTP request.
   * @return true if the IP is allowed, false otherwise.
   */
  boolean isIPAllowed(HttpServletRequest request);

  /**
   * Checks if the request path is on the allow list.
   * @param request the incoming HTTP request.
   * @return true if the path is allowed, false otherwise.
   */
  boolean isPathAllowed(HttpServletRequest request);

  /**
   * Checks if the request IP has a reverse DNS that matches the allow list.
   * @param request the incoming HTTP request.
   * @return true if the reverse DNS is allowed, false otherwise.
   */
  boolean isReverseDNSAllowed(HttpServletRequest request);

}
